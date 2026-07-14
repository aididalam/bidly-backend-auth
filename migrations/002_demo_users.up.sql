-- Sandbox-only demo accounts. INSERT IGNORE keeps real accounts and changed
-- passwords intact on subsequent service starts.
INSERT IGNORE INTO users (id, name, email, password_hash) VALUES
  ('11111111-1111-4111-8111-111111111111', 'Amina Rahman', 'user1@bidly.com', '$2y$10$EsnqF/z/8K.o7gPLBzqgz.CXGzT9Xxh64nbyQjmtid9LlT03OAxwu'),
  ('22222222-2222-4222-8222-222222222222', 'Nabil Hasan', 'user2@bidly.com', '$2y$10$EsnqF/z/8K.o7gPLBzqgz.CXGzT9Xxh64nbyQjmtid9LlT03OAxwu'),
  ('33333333-3333-4333-8333-333333333333', 'Farah Ahmed', 'user3@bidly.com', '$2y$10$EsnqF/z/8K.o7gPLBzqgz.CXGzT9Xxh64nbyQjmtid9LlT03OAxwu'),
  ('44444444-4444-4444-8444-444444444444', 'Tariq Mahmud', 'user4@bidly.com', '$2y$10$EsnqF/z/8K.o7gPLBzqgz.CXGzT9Xxh64nbyQjmtid9LlT03OAxwu'),
  ('55555555-5555-4555-8555-555555555555', 'Samira Noor', 'user5@bidly.com', '$2y$10$EsnqF/z/8K.o7gPLBzqgz.CXGzT9Xxh64nbyQjmtid9LlT03OAxwu');
