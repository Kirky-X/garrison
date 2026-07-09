-- Migration: 角色层级表（MySQL 版本，v0.5.0 新增，依据 proposal H6）
-- 对应 spec: role-hierarchy（TC 预计算）
-- 数据库: MySQL 8.0+
-- 幂等性: CREATE TABLE 使用 IF NOT EXISTS；MySQL 不支持 CREATE INDEX IF NOT EXISTS，故省略
--
-- 用途：存储 child_role → parent_role 的继承边，支持多租户隔离。
-- RoleHierarchyService.compute_closure() 读取此表计算传递闭包（间接祖先）。

-- UP:

CREATE TABLE IF NOT EXISTS role_hierarchy (
    tenant_id   BIGINT  NOT NULL DEFAULT 0,   -- 租户 ID（i64，0=默认租户）
    child_role  VARCHAR(255) NOT NULL,          -- 子角色编码（继承方）
    parent_role VARCHAR(255) NOT NULL,          -- 父角色编码（被继承方）
    PRIMARY KEY (tenant_id, child_role, parent_role)
);

-- 查询索引：按租户 + 子角色查询所有父角色（compute_closure DFS 遍历用）
CREATE INDEX idx_role_hierarchy_tenant_child
    ON role_hierarchy (tenant_id, child_role);

-- 查询索引：按租户 + 父角色查询所有子角色（反向查询，add_edge 去重用）
CREATE INDEX idx_role_hierarchy_tenant_parent
    ON role_hierarchy (tenant_id, parent_role);

-- DOWN:

DROP TABLE IF EXISTS role_hierarchy;
