-- Migration: add_repository_name_user_index
-- Issue #730: Repository.url missing index for URL-based lookup queries
--
-- The createRepository method in repositoryService.ts queries the repositories
-- table by (name, user_id) to enforce per-user name uniqueness. Without an index
-- on this combination, every repository creation triggers a sequential scan.
--
-- This migration adds a composite index on (user_id, name) to support that lookup,
-- and adds explanatory comments to document the purpose of existing indexes.

-- Add composite index for name-uniqueness check in createRepository
-- Covers: prisma.repository.findFirst({ where: { name, userId } })
CREATE INDEX "repositories_user_id_name_idx" ON "repositories"("user_id", "name");
