import { mysqlTable, varchar, int, timestamp, json, boolean } from "drizzle-orm/mysql-core";

export const users = mysqlTable("shops", {
    id: int("id").primaryKey().autoincrement(),
    email: varchar("email", { length: 255 }).unique().notNull(),
    password: varchar("password", { length: 255 }).notNull(),
    fcmToken: varchar("fcm_token", { length: 255 }),
    username: varchar("username", { length: 255 }),
    shopname: varchar("shopname", { length: 255 }),
    address: varchar("address", { length: 255 }),
    profileImageURL: varchar("profile_image_url", { length: 255 }),
    plan: varchar("plan", { length: 50 }),
    category: varchar("category", { length: 50 }),
    mp_access_token: varchar("mp_access_token", { length: 255 }),
    mp_refresh_token: varchar("mp_refresh_token", { length: 255 }),
    mp_token_expires: int("mp_token_expires"),
    connected_mp: int("connected_mp"),
    lastPaymentDate: timestamp("last_payment_date"),
    nextPaymentDate: timestamp("next_payment"),
    businessHours: json("business_hours"),
    createdAt: timestamp("created_at").notNull(),
    whatsappNumber: varchar('whatsapp_number', { length: 50 }),
    includeDelivery: boolean("include_delivery").default(false),
    deliveryCost: int("delivery_cost"), // Nuevo campo
});

// Las demás tablas (products, orders, orderItems) no requieren cambios
export const products = mysqlTable("products", {
    id: int("id").primaryKey().autoincrement(),
    name: varchar("name", { length: 255 }).notNull(),
    price: int("price").notNull(),
    description: varchar("description", { length: 255 }),
    imageURL: varchar("image_url", { length: 255 }),
    sizes: json("sizes"),
    stock: int("stock"),
    createdAt: timestamp("created_at").notNull(),
    createdBy: varchar("created_by", { length: 255 }),
    createdById: int("created_by_id").references(() => users.id),
});

export const orders = mysqlTable("orders", {
    id: int("id").primaryKey().autoincrement(),
    totalPrice: int("total_price").notNull(),
    phoneNumber: varchar("phone_number", { length: 255 }).notNull(),
    address: varchar("address", { length: 255 }),
    paymentMethod: varchar("payment_method", { length: 255 }).notNull(),
    paid: int("paid").notNull(),
    deliveryType: varchar("delivery_type", { length: 255 }).notNull(),
    createdAt: timestamp("created_at").notNull(),
    shopUsername: varchar("shop_username", { length: 255 }).references(() => users.username),
});

export const orderItems = mysqlTable("order_items", {
    id: int("id").primaryKey().autoincrement(),
    orderId: int("order_id").references(() => orders.id).notNull(),
    productId: int("product_id").notNull(),
    size: varchar("size", { length: 255 }),
    comment: varchar("comment", { length: 255 }),
});

export const images = mysqlTable("images", {
    id: int("id").primaryKey().autoincrement(),
    url: varchar("url", { length: 255 }).notNull(),
    productId: int("product_id").references(() => products.id).notNull(),
});