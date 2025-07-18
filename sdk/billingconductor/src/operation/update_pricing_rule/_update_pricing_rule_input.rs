// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdatePricingRuleInput {
    /// <p>The Amazon Resource Name (ARN) of the pricing rule to update.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The new name of the pricing rule. The name must be unique to each pricing rule.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The new description for the pricing rule.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The new pricing rule type.</p>
    pub r#type: ::std::option::Option<crate::types::PricingRuleType>,
    /// <p>The new modifier to show pricing plan rates as a percentage.</p>
    pub modifier_percentage: ::std::option::Option<f64>,
    /// <p>The set of tiering configurations for the pricing rule.</p>
    pub tiering: ::std::option::Option<crate::types::UpdateTieringInput>,
}
impl UpdatePricingRuleInput {
    /// <p>The Amazon Resource Name (ARN) of the pricing rule to update.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The new name of the pricing rule. The name must be unique to each pricing rule.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The new description for the pricing rule.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The new pricing rule type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::PricingRuleType> {
        self.r#type.as_ref()
    }
    /// <p>The new modifier to show pricing plan rates as a percentage.</p>
    pub fn modifier_percentage(&self) -> ::std::option::Option<f64> {
        self.modifier_percentage
    }
    /// <p>The set of tiering configurations for the pricing rule.</p>
    pub fn tiering(&self) -> ::std::option::Option<&crate::types::UpdateTieringInput> {
        self.tiering.as_ref()
    }
}
impl ::std::fmt::Debug for UpdatePricingRuleInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatePricingRuleInput");
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &self.r#type);
        formatter.field("modifier_percentage", &self.modifier_percentage);
        formatter.field("tiering", &self.tiering);
        formatter.finish()
    }
}
impl UpdatePricingRuleInput {
    /// Creates a new builder-style object to manufacture [`UpdatePricingRuleInput`](crate::operation::update_pricing_rule::UpdatePricingRuleInput).
    pub fn builder() -> crate::operation::update_pricing_rule::builders::UpdatePricingRuleInputBuilder {
        crate::operation::update_pricing_rule::builders::UpdatePricingRuleInputBuilder::default()
    }
}

/// A builder for [`UpdatePricingRuleInput`](crate::operation::update_pricing_rule::UpdatePricingRuleInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdatePricingRuleInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::PricingRuleType>,
    pub(crate) modifier_percentage: ::std::option::Option<f64>,
    pub(crate) tiering: ::std::option::Option<crate::types::UpdateTieringInput>,
}
impl UpdatePricingRuleInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the pricing rule to update.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pricing rule to update.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pricing rule to update.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The new name of the pricing rule. The name must be unique to each pricing rule.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name of the pricing rule. The name must be unique to each pricing rule.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The new name of the pricing rule. The name must be unique to each pricing rule.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The new description for the pricing rule.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description for the pricing rule.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description for the pricing rule.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The new pricing rule type.</p>
    pub fn r#type(mut self, input: crate::types::PricingRuleType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new pricing rule type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::PricingRuleType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The new pricing rule type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::PricingRuleType> {
        &self.r#type
    }
    /// <p>The new modifier to show pricing plan rates as a percentage.</p>
    pub fn modifier_percentage(mut self, input: f64) -> Self {
        self.modifier_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new modifier to show pricing plan rates as a percentage.</p>
    pub fn set_modifier_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.modifier_percentage = input;
        self
    }
    /// <p>The new modifier to show pricing plan rates as a percentage.</p>
    pub fn get_modifier_percentage(&self) -> &::std::option::Option<f64> {
        &self.modifier_percentage
    }
    /// <p>The set of tiering configurations for the pricing rule.</p>
    pub fn tiering(mut self, input: crate::types::UpdateTieringInput) -> Self {
        self.tiering = ::std::option::Option::Some(input);
        self
    }
    /// <p>The set of tiering configurations for the pricing rule.</p>
    pub fn set_tiering(mut self, input: ::std::option::Option<crate::types::UpdateTieringInput>) -> Self {
        self.tiering = input;
        self
    }
    /// <p>The set of tiering configurations for the pricing rule.</p>
    pub fn get_tiering(&self) -> &::std::option::Option<crate::types::UpdateTieringInput> {
        &self.tiering
    }
    /// Consumes the builder and constructs a [`UpdatePricingRuleInput`](crate::operation::update_pricing_rule::UpdatePricingRuleInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_pricing_rule::UpdatePricingRuleInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_pricing_rule::UpdatePricingRuleInput {
            arn: self.arn,
            name: self.name,
            description: self.description,
            r#type: self.r#type,
            modifier_percentage: self.modifier_percentage,
            tiering: self.tiering,
        })
    }
}
impl ::std::fmt::Debug for UpdatePricingRuleInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdatePricingRuleInputBuilder");
        formatter.field("arn", &self.arn);
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &self.r#type);
        formatter.field("modifier_percentage", &self.modifier_percentage);
        formatter.field("tiering", &self.tiering);
        formatter.finish()
    }
}
