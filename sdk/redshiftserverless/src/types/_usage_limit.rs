// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The usage limit object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UsageLimit {
    /// <p>The identifier of the usage limit.</p>
    pub usage_limit_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the resource associated with the usage limit.</p>
    pub usage_limit_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) that identifies the Amazon Redshift Serverless resource.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Redshift Serverless feature to limit.</p>
    pub usage_type: ::std::option::Option<crate::types::UsageLimitUsageType>,
    /// <p>The limit amount. If time-based, this amount is in RPUs consumed per hour. If data-based, this amount is in terabytes (TB). The value must be a positive number.</p>
    pub amount: ::std::option::Option<i64>,
    /// <p>The time period that the amount applies to. A weekly period begins on Sunday. The default is monthly.</p>
    pub period: ::std::option::Option<crate::types::UsageLimitPeriod>,
    /// <p>The action that Amazon Redshift Serverless takes when the limit is reached.</p>
    pub breach_action: ::std::option::Option<crate::types::UsageLimitBreachAction>,
}
impl UsageLimit {
    /// <p>The identifier of the usage limit.</p>
    pub fn usage_limit_id(&self) -> ::std::option::Option<&str> {
        self.usage_limit_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the resource associated with the usage limit.</p>
    pub fn usage_limit_arn(&self) -> ::std::option::Option<&str> {
        self.usage_limit_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the Amazon Redshift Serverless resource.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>The Amazon Redshift Serverless feature to limit.</p>
    pub fn usage_type(&self) -> ::std::option::Option<&crate::types::UsageLimitUsageType> {
        self.usage_type.as_ref()
    }
    /// <p>The limit amount. If time-based, this amount is in RPUs consumed per hour. If data-based, this amount is in terabytes (TB). The value must be a positive number.</p>
    pub fn amount(&self) -> ::std::option::Option<i64> {
        self.amount
    }
    /// <p>The time period that the amount applies to. A weekly period begins on Sunday. The default is monthly.</p>
    pub fn period(&self) -> ::std::option::Option<&crate::types::UsageLimitPeriod> {
        self.period.as_ref()
    }
    /// <p>The action that Amazon Redshift Serverless takes when the limit is reached.</p>
    pub fn breach_action(&self) -> ::std::option::Option<&crate::types::UsageLimitBreachAction> {
        self.breach_action.as_ref()
    }
}
impl UsageLimit {
    /// Creates a new builder-style object to manufacture [`UsageLimit`](crate::types::UsageLimit).
    pub fn builder() -> crate::types::builders::UsageLimitBuilder {
        crate::types::builders::UsageLimitBuilder::default()
    }
}

/// A builder for [`UsageLimit`](crate::types::UsageLimit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UsageLimitBuilder {
    pub(crate) usage_limit_id: ::std::option::Option<::std::string::String>,
    pub(crate) usage_limit_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) usage_type: ::std::option::Option<crate::types::UsageLimitUsageType>,
    pub(crate) amount: ::std::option::Option<i64>,
    pub(crate) period: ::std::option::Option<crate::types::UsageLimitPeriod>,
    pub(crate) breach_action: ::std::option::Option<crate::types::UsageLimitBreachAction>,
}
impl UsageLimitBuilder {
    /// <p>The identifier of the usage limit.</p>
    pub fn usage_limit_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_limit_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the usage limit.</p>
    pub fn set_usage_limit_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_limit_id = input;
        self
    }
    /// <p>The identifier of the usage limit.</p>
    pub fn get_usage_limit_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_limit_id
    }
    /// <p>The Amazon Resource Name (ARN) of the resource associated with the usage limit.</p>
    pub fn usage_limit_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_limit_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource associated with the usage limit.</p>
    pub fn set_usage_limit_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_limit_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the resource associated with the usage limit.</p>
    pub fn get_usage_limit_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_limit_arn
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the Amazon Redshift Serverless resource.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the Amazon Redshift Serverless resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the Amazon Redshift Serverless resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// <p>The Amazon Redshift Serverless feature to limit.</p>
    pub fn usage_type(mut self, input: crate::types::UsageLimitUsageType) -> Self {
        self.usage_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Redshift Serverless feature to limit.</p>
    pub fn set_usage_type(mut self, input: ::std::option::Option<crate::types::UsageLimitUsageType>) -> Self {
        self.usage_type = input;
        self
    }
    /// <p>The Amazon Redshift Serverless feature to limit.</p>
    pub fn get_usage_type(&self) -> &::std::option::Option<crate::types::UsageLimitUsageType> {
        &self.usage_type
    }
    /// <p>The limit amount. If time-based, this amount is in RPUs consumed per hour. If data-based, this amount is in terabytes (TB). The value must be a positive number.</p>
    pub fn amount(mut self, input: i64) -> Self {
        self.amount = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit amount. If time-based, this amount is in RPUs consumed per hour. If data-based, this amount is in terabytes (TB). The value must be a positive number.</p>
    pub fn set_amount(mut self, input: ::std::option::Option<i64>) -> Self {
        self.amount = input;
        self
    }
    /// <p>The limit amount. If time-based, this amount is in RPUs consumed per hour. If data-based, this amount is in terabytes (TB). The value must be a positive number.</p>
    pub fn get_amount(&self) -> &::std::option::Option<i64> {
        &self.amount
    }
    /// <p>The time period that the amount applies to. A weekly period begins on Sunday. The default is monthly.</p>
    pub fn period(mut self, input: crate::types::UsageLimitPeriod) -> Self {
        self.period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time period that the amount applies to. A weekly period begins on Sunday. The default is monthly.</p>
    pub fn set_period(mut self, input: ::std::option::Option<crate::types::UsageLimitPeriod>) -> Self {
        self.period = input;
        self
    }
    /// <p>The time period that the amount applies to. A weekly period begins on Sunday. The default is monthly.</p>
    pub fn get_period(&self) -> &::std::option::Option<crate::types::UsageLimitPeriod> {
        &self.period
    }
    /// <p>The action that Amazon Redshift Serverless takes when the limit is reached.</p>
    pub fn breach_action(mut self, input: crate::types::UsageLimitBreachAction) -> Self {
        self.breach_action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action that Amazon Redshift Serverless takes when the limit is reached.</p>
    pub fn set_breach_action(mut self, input: ::std::option::Option<crate::types::UsageLimitBreachAction>) -> Self {
        self.breach_action = input;
        self
    }
    /// <p>The action that Amazon Redshift Serverless takes when the limit is reached.</p>
    pub fn get_breach_action(&self) -> &::std::option::Option<crate::types::UsageLimitBreachAction> {
        &self.breach_action
    }
    /// Consumes the builder and constructs a [`UsageLimit`](crate::types::UsageLimit).
    pub fn build(self) -> crate::types::UsageLimit {
        crate::types::UsageLimit {
            usage_limit_id: self.usage_limit_id,
            usage_limit_arn: self.usage_limit_arn,
            resource_arn: self.resource_arn,
            usage_type: self.usage_type,
            amount: self.amount,
            period: self.period,
            breach_action: self.breach_action,
        }
    }
}
