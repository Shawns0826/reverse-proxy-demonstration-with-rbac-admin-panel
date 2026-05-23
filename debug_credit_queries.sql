-- Debug Credit Transactions
-- Run these queries in your database to investigate the credit deduction issue

-- 1. Check the reseller's current credits and role
SELECT id, username, role, credits, initial_credits, created_at 
FROM "user" 
WHERE username = 'resellertest';

-- 2. Check all credit transactions for the reseller (most recent first)
SELECT 
    cl.id,
    cl.action_type,
    cl.credits_amount,
    cl.credits_before,
    cl.credits_after,
    cl.performed_by,
    cl.notes,
    cl.created_at,
    u.username as user_username
FROM credit_log cl
JOIN "user" u ON cl.user_id = u.id
WHERE u.username = 'resellertest'
ORDER BY cl.created_at DESC
LIMIT 10;

-- 3. Check all credit transactions in the system (most recent first)
SELECT 
    cl.id,
    cl.action_type,
    cl.credits_amount,
    cl.credits_before,
    cl.credits_after,
    cl.performed_by,
    cl.notes,
    cl.created_at,
    u.username as user_username,
    u.role as user_role
FROM credit_log cl
JOIN "user" u ON cl.user_id = u.id
ORDER BY cl.created_at DESC
LIMIT 20;

-- 4. Check if there are any TRANSFER transactions (reseller credit deductions)
SELECT 
    cl.id,
    cl.action_type,
    cl.credits_amount,
    cl.credits_before,
    cl.credits_after,
    cl.performed_by,
    cl.notes,
    cl.created_at,
    u.username as user_username,
    u.role as user_role
FROM credit_log cl
JOIN "user" u ON cl.user_id = u.id
WHERE cl.action_type = 'TRANSFER'
ORDER BY cl.created_at DESC
LIMIT 10;

-- 5. Check if there are any EXTEND transactions (customer credit additions)
SELECT 
    cl.id,
    cl.action_type,
    cl.credits_amount,
    cl.credits_before,
    cl.credits_after,
    cl.performed_by,
    cl.notes,
    cl.created_at,
    u.username as user_username,
    u.role as user_role
FROM credit_log cl
JOIN "user" u ON cl.user_id = u.id
WHERE cl.action_type = 'EXTEND'
ORDER BY cl.created_at DESC
LIMIT 10;

-- 6. Check all users and their current credits
SELECT id, username, role, credits, initial_credits, created_at 
FROM "user" 
ORDER BY created_at DESC;

-- 7. Check recent transactions by a specific user (replace 'username' with actual username)
-- SELECT 
--     cl.id,
--     cl.action_type,
--     cl.credits_amount,
--     cl.credits_before,
--     cl.credits_after,
--     cl.performed_by,
--     cl.notes,
--     cl.created_at
-- FROM credit_log cl
-- JOIN "user" u ON cl.user_id = u.id
-- WHERE u.username = 'username'
-- ORDER BY cl.created_at DESC
-- LIMIT 10; 