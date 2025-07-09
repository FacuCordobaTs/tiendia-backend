import { mysqlTable, varchar, int, timestamp, text, boolean, date } from "drizzle-orm/mysql-core";

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
    imageUrl: varchar("image_url", { length: 255 }),
    name: varchar("name", { length: 255 }),
    username: varchar("username", { length: 255 }).unique(),
    phone: varchar("phone", { length: 255 }),
});

export const products = mysqlTable("products", {
    id: int("id").primaryKey().autoincrement(),
    name: varchar("name", { length: 255 }).notNull(),
    imageURL: varchar("image_url", { length: 255 }),
    createdAt: timestamp("created_at").notNull(),
    createdById: int("createdById").references(() => users.id),
    price: int("price"),
    sizes: text("sizes"),
});

export const images = mysqlTable("images", {
    id: int("id").primaryKey().autoincrement(),
    url: varchar("url", { length: 255 }).notNull(),
    productId: int("productId").references(() => products.id).notNull(),
    createdAt: timestamp("created_at").notNull(),
});

export const creditPurchases = mysqlTable("credit_purchases", {
    id: int("id").primaryKey().autoincrement(),
    userId: int("user_id").notNull().references(() => users.id),
    credits: int("credits").notNull(),
    priceArs: int("price_ars").notNull(),
    productsReferenceId: varchar("preference_id", { length: 255 }),
    createdAt: timestamp("created_at").defaultNow(),
});
  
  export const imageGenerations = mysqlTable("image_generations", {
    id: int("id").primaryKey().autoincrement(),
    userId: int("user_id").notNull().references(() => users.id),
    productId: int("product_id").references(() => products.id),
    createdAt: timestamp("created_at").defaultNow(),
});