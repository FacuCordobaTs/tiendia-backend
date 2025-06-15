import { mysqlTable, varchar, int, timestamp, text, boolean } from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
    id: int("id").primaryKey().autoincrement(),
    email: varchar("email", { length: 255 }).unique().notNull(),
    password: varchar("password", { length: 255 }),
    createdAt: timestamp("created_at").notNull(),
    googleId: varchar('google_id', { length: 255 }).unique(),
    credits: int("credits").default(0),
    lastPreferenceId: varchar("last_preference_id", { length: 255 }),
    lastPreferencePaid: boolean("last_preference_paid").default(false),
    suscriptionId: varchar("suscription_id", { length: 255 }),
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