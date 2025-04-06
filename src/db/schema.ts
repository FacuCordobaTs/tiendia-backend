import { mysqlTable, varchar, int, timestamp } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
    id: int("id").primaryKey().autoincrement(),
    email: varchar("email", { length: 255 }).unique().notNull(),
    password: varchar("password", { length: 255 }).notNull(),
    category: varchar("category", { length: 50 }),
    createdAt: timestamp("created_at").notNull()
});

export const products = mysqlTable("products", {
    id: int("id").primaryKey().autoincrement(),
    name: varchar("name", { length: 255 }).notNull(),
    imageURL: varchar("image_url", { length: 255 }),
    createdAt: timestamp("created_at").notNull(),
    createdById: int("createdById").references(() => users.id),
});

export const images = mysqlTable("images", {
    id: int("id").primaryKey().autoincrement(),
    url: varchar("url", { length: 255 }).notNull(),
    productId: int("productId").references(() => products.id).notNull(),
    createdAt: timestamp("created_at").notNull(),
});