-- Shop Ledger: initial schema and atomic ledger operations.

create type public.transaction_type as enum ('debt', 'payment');

create table public.customers (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null default auth.uid() references auth.users (id) on delete restrict,
    name text not null check (length(btrim(name)) between 1 and 120),
    phone text null check (phone is null or length(phone) <= 40),
    balance numeric(14, 2) not null default 0 check (balance >= 0),
    created_at timestamptz not null default now(),
    constraint customers_owner_id_id_key unique (owner_id, id)
);

create table public.transactions (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null references auth.users (id) on delete restrict,
    customer_id uuid not null,
    type public.transaction_type not null,
    amount numeric(14, 2) not null check (amount > 0),
    description text null check (description is null or length(description) <= 500),
    idempotency_key uuid not null,
    created_at timestamptz not null default now(),
    constraint transactions_owner_customer_fk
        foreign key (owner_id, customer_id)
        references public.customers (owner_id, id) on delete restrict,
    constraint transactions_owner_id_id_key unique (owner_id, id),
    constraint transactions_owner_customer_id_id_key unique (owner_id, customer_id, id),
    constraint transactions_owner_idempotency_key unique (owner_id, idempotency_key)
);

-- A correction changes the effective amount of an original debt/payment.
-- Positive amount_delta increases the original amount; negative decreases it.
-- Corrections always reference an original transaction, never another correction.
create table public.transaction_corrections (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null references auth.users (id) on delete restrict,
    customer_id uuid not null,
    original_transaction_id uuid not null,
    amount_delta numeric(14, 2) not null check (amount_delta <> 0),
    description text null check (description is null or length(description) <= 500),
    idempotency_key uuid not null,
    created_at timestamptz not null default now(),
    constraint corrections_owner_customer_fk
        foreign key (owner_id, customer_id)
        references public.customers (owner_id, id) on delete restrict,
    constraint corrections_original_transaction_fk
        foreign key (owner_id, customer_id, original_transaction_id)
        references public.transactions (owner_id, customer_id, id) on delete restrict,
    constraint corrections_owner_idempotency_key unique (owner_id, idempotency_key)
);

create index customers_owner_name_idx
    on public.customers (owner_id, lower(name));
create index transactions_owner_created_at_idx
    on public.transactions (owner_id, created_at desc, id desc);
create index transactions_customer_created_at_idx
    on public.transactions (customer_id, created_at desc, id desc);
create index corrections_original_transaction_idx
    on public.transaction_corrections (original_transaction_id, created_at, id);
create index corrections_owner_created_at_idx
    on public.transaction_corrections (owner_id, created_at desc, id desc);

alter table public.customers enable row level security;
alter table public.transactions enable row level security;
alter table public.transaction_corrections enable row level security;

create policy customers_select_own
    on public.customers for select to authenticated
    using (owner_id = (select auth.uid()));
create policy customers_insert_own
    on public.customers for insert to authenticated
    with check (owner_id = (select auth.uid()));
create policy customers_update_own
    on public.customers for update to authenticated
    using (owner_id = (select auth.uid()))
    with check (owner_id = (select auth.uid()));

create policy transactions_select_own
    on public.transactions for select to authenticated
    using (owner_id = (select auth.uid()));
create policy corrections_select_own
    on public.transaction_corrections for select to authenticated
    using (owner_id = (select auth.uid()));

-- Revoke broad defaults, then grant only the operations the mobile client needs.
revoke all on public.customers from anon, authenticated;
revoke all on public.transactions from anon, authenticated;
revoke all on public.transaction_corrections from anon, authenticated;
revoke all on type public.transaction_type from anon, authenticated;

grant select on public.customers to authenticated;
grant insert (name, phone) on public.customers to authenticated;
grant update (name, phone) on public.customers to authenticated;
grant select on public.transactions to authenticated;
grant select on public.transaction_corrections to authenticated;
grant usage on type public.transaction_type to authenticated;

create or replace function public.create_customer_transaction(
    p_customer_id uuid,
    p_type public.transaction_type,
    p_amount numeric,
    p_description text,
    p_idempotency_key uuid
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_owner_id uuid := auth.uid();
    v_balance numeric(14, 2);
    v_existing public.transactions%rowtype;
    v_transaction_id uuid;
    v_description text := nullif(btrim(p_description), '');
begin
    if v_owner_id is null then
        raise exception using errcode = '42501', message = 'Authentication required.';
    end if;
    if p_customer_id is null or p_type is null or p_amount is null or p_amount <= 0
       or p_amount <> round(p_amount, 2) or p_idempotency_key is null then
        raise exception using errcode = '22023', message = 'Amount must be positive and have at most two decimal places; all required fields must be supplied.';
    end if;
    if v_description is not null and length(v_description) > 500 then
        raise exception using errcode = '22023', message = 'Description must not exceed 500 characters.';
    end if;

    -- Serialize all ledger mutations for this customer.
    select c.balance
      into v_balance
      from public.customers as c
     where c.id = p_customer_id
       and c.owner_id = v_owner_id
     for update;

    if not found then
        raise exception using errcode = 'P0002', message = 'Customer not found.';
    end if;

    -- Retries with the same key return the original result; key reuse with a
    -- different payload is rejected rather than silently accepted.
    select t.*
      into v_existing
      from public.transactions as t
     where t.owner_id = v_owner_id
       and t.idempotency_key = p_idempotency_key;

    if found then
        if v_existing.customer_id is distinct from p_customer_id
           or v_existing.type is distinct from p_type
           or v_existing.amount is distinct from p_amount
           or v_existing.description is distinct from v_description then
            raise exception using errcode = '22023', message = 'Idempotency key was already used with a different request.';
        end if;
        return v_existing.id;
    end if;

    if p_type = 'payment' and p_amount > v_balance then
        raise exception using errcode = '22023', message = 'Payment exceeds the outstanding balance.';
    end if;

    insert into public.transactions (
        owner_id, customer_id, type, amount, description, idempotency_key
    ) values (
        v_owner_id, p_customer_id, p_type, p_amount, v_description, p_idempotency_key
    ) returning id into v_transaction_id;

    update public.customers
       set balance = balance + case when p_type = 'debt' then p_amount else -p_amount end
     where id = p_customer_id
       and owner_id = v_owner_id;

    return v_transaction_id;
end;
$$;

create or replace function public.correct_customer_transaction(
    p_original_transaction_id uuid,
    p_amount_delta numeric,
    p_description text,
    p_idempotency_key uuid
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
    v_owner_id uuid := auth.uid();
    v_customer_id uuid;
    v_original_type public.transaction_type;
    v_original_amount numeric(14, 2);
    v_effective_amount numeric(14, 2);
    v_balance numeric(14, 2);
    v_balance_delta numeric(14, 2);
    v_existing public.transaction_corrections%rowtype;
    v_correction_id uuid;
    v_description text := nullif(btrim(p_description), '');
begin
    if v_owner_id is null then
        raise exception using errcode = '42501', message = 'Authentication required.';
    end if;
    if p_original_transaction_id is null or p_amount_delta is null
       or p_amount_delta = 0 or p_amount_delta <> round(p_amount_delta, 2)
       or p_idempotency_key is null then
        raise exception using errcode = '22023', message = 'Correction must be non-zero, have at most two decimal places, and include all required fields.';
    end if;
    if v_description is not null and length(v_description) > 500 then
        raise exception using errcode = '22023', message = 'Description must not exceed 500 characters.';
    end if;

    -- Resolve the original entry and lock its customer before calculating the
    -- cumulative correction. All ledger mutation functions use this lock order.
    select t.customer_id, t.type, t.amount
      into v_customer_id, v_original_type, v_original_amount
      from public.transactions as t
     where t.id = p_original_transaction_id
       and t.owner_id = v_owner_id;

    if not found then
        raise exception using errcode = 'P0002', message = 'Original transaction not found.';
    end if;

    select c.balance
      into v_balance
      from public.customers as c
     where c.id = v_customer_id
       and c.owner_id = v_owner_id
     for update;

    if not found then
        raise exception using errcode = 'P0002', message = 'Customer not found.';
    end if;

    select c.*
      into v_existing
      from public.transaction_corrections as c
     where c.owner_id = v_owner_id
       and c.idempotency_key = p_idempotency_key;

    if found then
        if v_existing.customer_id is distinct from v_customer_id
           or v_existing.original_transaction_id is distinct from p_original_transaction_id
           or v_existing.amount_delta is distinct from p_amount_delta
           or v_existing.description is distinct from v_description then
            raise exception using errcode = '22023', message = 'Idempotency key was already used with a different request.';
        end if;
        return v_existing.id;
    end if;

    select v_original_amount + coalesce(sum(c.amount_delta), 0)
      into v_effective_amount
      from public.transaction_corrections as c
     where c.owner_id = v_owner_id
       and c.original_transaction_id = p_original_transaction_id;

    if v_effective_amount + p_amount_delta < 0 then
        raise exception using errcode = '22023', message = 'Correction would make the original transaction amount negative.';
    end if;

    -- Debt amount increases debt; payment amount increases reduce debt.
    v_balance_delta := case
        when v_original_type = 'debt' then p_amount_delta
        else -p_amount_delta
    end;

    if v_balance + v_balance_delta < 0 then
        raise exception using errcode = '22023', message = 'Correction would make the customer balance negative.';
    end if;

    insert into public.transaction_corrections (
        owner_id, customer_id, original_transaction_id,
        amount_delta, description, idempotency_key
    ) values (
        v_owner_id, v_customer_id, p_original_transaction_id,
        p_amount_delta, v_description, p_idempotency_key
    ) returning id into v_correction_id;

    update public.customers
       set balance = balance + v_balance_delta
     where id = v_customer_id
       and owner_id = v_owner_id;

    return v_correction_id;
end;
$$;

revoke all on function public.create_customer_transaction(uuid, public.transaction_type, numeric, text, uuid) from public, anon;
revoke all on function public.correct_customer_transaction(uuid, numeric, text, uuid) from public, anon;
grant execute on function public.create_customer_transaction(uuid, public.transaction_type, numeric, text, uuid) to authenticated;
grant execute on function public.correct_customer_transaction(uuid, numeric, text, uuid) to authenticated;
