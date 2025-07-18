// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The types of cost that are included in a <code>COST</code> budget, such as tax and subscriptions.</p>
/// <p><code>USAGE</code>, <code>RI_UTILIZATION</code>, <code>RI_COVERAGE</code>, <code>SAVINGS_PLANS_UTILIZATION</code>, and <code>SAVINGS_PLANS_COVERAGE</code> budgets don't have <code>CostTypes</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CostTypes {
    /// <p>Specifies whether a budget includes taxes.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_tax: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes subscriptions.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_subscription: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget uses a blended rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub use_blended: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes refunds.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_refund: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes credits.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_credit: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes upfront RI costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_upfront: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes recurring fees such as monthly RI fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_recurring: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes non-RI subscription costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_other_subscription: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes support subscription fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_support: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget includes discounts.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub include_discount: ::std::option::Option<bool>,
    /// <p>Specifies whether a budget uses the amortized rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub use_amortized: ::std::option::Option<bool>,
}
impl CostTypes {
    /// <p>Specifies whether a budget includes taxes.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_tax(&self) -> ::std::option::Option<bool> {
        self.include_tax
    }
    /// <p>Specifies whether a budget includes subscriptions.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_subscription(&self) -> ::std::option::Option<bool> {
        self.include_subscription
    }
    /// <p>Specifies whether a budget uses a blended rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn use_blended(&self) -> ::std::option::Option<bool> {
        self.use_blended
    }
    /// <p>Specifies whether a budget includes refunds.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_refund(&self) -> ::std::option::Option<bool> {
        self.include_refund
    }
    /// <p>Specifies whether a budget includes credits.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_credit(&self) -> ::std::option::Option<bool> {
        self.include_credit
    }
    /// <p>Specifies whether a budget includes upfront RI costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_upfront(&self) -> ::std::option::Option<bool> {
        self.include_upfront
    }
    /// <p>Specifies whether a budget includes recurring fees such as monthly RI fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_recurring(&self) -> ::std::option::Option<bool> {
        self.include_recurring
    }
    /// <p>Specifies whether a budget includes non-RI subscription costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_other_subscription(&self) -> ::std::option::Option<bool> {
        self.include_other_subscription
    }
    /// <p>Specifies whether a budget includes support subscription fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_support(&self) -> ::std::option::Option<bool> {
        self.include_support
    }
    /// <p>Specifies whether a budget includes discounts.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_discount(&self) -> ::std::option::Option<bool> {
        self.include_discount
    }
    /// <p>Specifies whether a budget uses the amortized rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn use_amortized(&self) -> ::std::option::Option<bool> {
        self.use_amortized
    }
}
impl CostTypes {
    /// Creates a new builder-style object to manufacture [`CostTypes`](crate::types::CostTypes).
    pub fn builder() -> crate::types::builders::CostTypesBuilder {
        crate::types::builders::CostTypesBuilder::default()
    }
}

/// A builder for [`CostTypes`](crate::types::CostTypes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CostTypesBuilder {
    pub(crate) include_tax: ::std::option::Option<bool>,
    pub(crate) include_subscription: ::std::option::Option<bool>,
    pub(crate) use_blended: ::std::option::Option<bool>,
    pub(crate) include_refund: ::std::option::Option<bool>,
    pub(crate) include_credit: ::std::option::Option<bool>,
    pub(crate) include_upfront: ::std::option::Option<bool>,
    pub(crate) include_recurring: ::std::option::Option<bool>,
    pub(crate) include_other_subscription: ::std::option::Option<bool>,
    pub(crate) include_support: ::std::option::Option<bool>,
    pub(crate) include_discount: ::std::option::Option<bool>,
    pub(crate) use_amortized: ::std::option::Option<bool>,
}
impl CostTypesBuilder {
    /// <p>Specifies whether a budget includes taxes.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_tax(mut self, input: bool) -> Self {
        self.include_tax = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes taxes.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_tax(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_tax = input;
        self
    }
    /// <p>Specifies whether a budget includes taxes.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_tax(&self) -> &::std::option::Option<bool> {
        &self.include_tax
    }
    /// <p>Specifies whether a budget includes subscriptions.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_subscription(mut self, input: bool) -> Self {
        self.include_subscription = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes subscriptions.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_subscription(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_subscription = input;
        self
    }
    /// <p>Specifies whether a budget includes subscriptions.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_subscription(&self) -> &::std::option::Option<bool> {
        &self.include_subscription
    }
    /// <p>Specifies whether a budget uses a blended rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn use_blended(mut self, input: bool) -> Self {
        self.use_blended = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget uses a blended rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn set_use_blended(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_blended = input;
        self
    }
    /// <p>Specifies whether a budget uses a blended rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn get_use_blended(&self) -> &::std::option::Option<bool> {
        &self.use_blended
    }
    /// <p>Specifies whether a budget includes refunds.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_refund(mut self, input: bool) -> Self {
        self.include_refund = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes refunds.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_refund(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_refund = input;
        self
    }
    /// <p>Specifies whether a budget includes refunds.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_refund(&self) -> &::std::option::Option<bool> {
        &self.include_refund
    }
    /// <p>Specifies whether a budget includes credits.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_credit(mut self, input: bool) -> Self {
        self.include_credit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes credits.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_credit(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_credit = input;
        self
    }
    /// <p>Specifies whether a budget includes credits.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_credit(&self) -> &::std::option::Option<bool> {
        &self.include_credit
    }
    /// <p>Specifies whether a budget includes upfront RI costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_upfront(mut self, input: bool) -> Self {
        self.include_upfront = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes upfront RI costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_upfront(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_upfront = input;
        self
    }
    /// <p>Specifies whether a budget includes upfront RI costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_upfront(&self) -> &::std::option::Option<bool> {
        &self.include_upfront
    }
    /// <p>Specifies whether a budget includes recurring fees such as monthly RI fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_recurring(mut self, input: bool) -> Self {
        self.include_recurring = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes recurring fees such as monthly RI fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_recurring(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_recurring = input;
        self
    }
    /// <p>Specifies whether a budget includes recurring fees such as monthly RI fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_recurring(&self) -> &::std::option::Option<bool> {
        &self.include_recurring
    }
    /// <p>Specifies whether a budget includes non-RI subscription costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_other_subscription(mut self, input: bool) -> Self {
        self.include_other_subscription = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes non-RI subscription costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_other_subscription(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_other_subscription = input;
        self
    }
    /// <p>Specifies whether a budget includes non-RI subscription costs.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_other_subscription(&self) -> &::std::option::Option<bool> {
        &self.include_other_subscription
    }
    /// <p>Specifies whether a budget includes support subscription fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_support(mut self, input: bool) -> Self {
        self.include_support = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes support subscription fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_support(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_support = input;
        self
    }
    /// <p>Specifies whether a budget includes support subscription fees.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_support(&self) -> &::std::option::Option<bool> {
        &self.include_support
    }
    /// <p>Specifies whether a budget includes discounts.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn include_discount(mut self, input: bool) -> Self {
        self.include_discount = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget includes discounts.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn set_include_discount(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_discount = input;
        self
    }
    /// <p>Specifies whether a budget includes discounts.</p>
    /// <p>The default value is <code>true</code>.</p>
    pub fn get_include_discount(&self) -> &::std::option::Option<bool> {
        &self.include_discount
    }
    /// <p>Specifies whether a budget uses the amortized rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn use_amortized(mut self, input: bool) -> Self {
        self.use_amortized = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a budget uses the amortized rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn set_use_amortized(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_amortized = input;
        self
    }
    /// <p>Specifies whether a budget uses the amortized rate.</p>
    /// <p>The default value is <code>false</code>.</p>
    pub fn get_use_amortized(&self) -> &::std::option::Option<bool> {
        &self.use_amortized
    }
    /// Consumes the builder and constructs a [`CostTypes`](crate::types::CostTypes).
    pub fn build(self) -> crate::types::CostTypes {
        crate::types::CostTypes {
            include_tax: self.include_tax,
            include_subscription: self.include_subscription,
            use_blended: self.use_blended,
            include_refund: self.include_refund,
            include_credit: self.include_credit,
            include_upfront: self.include_upfront,
            include_recurring: self.include_recurring,
            include_other_subscription: self.include_other_subscription,
            include_support: self.include_support,
            include_discount: self.include_discount,
            use_amortized: self.use_amortized,
        }
    }
}
