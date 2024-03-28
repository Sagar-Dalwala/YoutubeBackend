import mongoose, { Schema } from "mongoose";

const subscriptionSchema = new Schema(
    {
        subscriber: {
            type: Schema.Types.ObjectId, // user who subscribe
            ref: "User",
        },
        channel: {
            type: Schema.Types.ObjectId, // user whom has subscriber is subscribed
            ref: "User",
        },
    },
    { timestamps: true }
);

export const Subscription = mongoose.model("Subscription", subscriptionSchema);
