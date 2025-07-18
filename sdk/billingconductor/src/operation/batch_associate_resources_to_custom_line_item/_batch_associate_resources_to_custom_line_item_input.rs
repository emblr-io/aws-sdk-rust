// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchAssociateResourcesToCustomLineItemInput {
    /// <p>A percentage custom line item ARN to associate the resources to.</p>
    pub target_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list containing the ARNs of the resources to be associated.</p>
    pub resource_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The billing period range in which the custom line item request will be applied.</p>
    pub billing_period_range: ::std::option::Option<crate::types::CustomLineItemBillingPeriodRange>,
}
impl BatchAssociateResourcesToCustomLineItemInput {
    /// <p>A percentage custom line item ARN to associate the resources to.</p>
    pub fn target_arn(&self) -> ::std::option::Option<&str> {
        self.target_arn.as_deref()
    }
    /// <p>A list containing the ARNs of the resources to be associated.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_arns.is_none()`.
    pub fn resource_arns(&self) -> &[::std::string::String] {
        self.resource_arns.as_deref().unwrap_or_default()
    }
    /// <p>The billing period range in which the custom line item request will be applied.</p>
    pub fn billing_period_range(&self) -> ::std::option::Option<&crate::types::CustomLineItemBillingPeriodRange> {
        self.billing_period_range.as_ref()
    }
}
impl BatchAssociateResourcesToCustomLineItemInput {
    /// Creates a new builder-style object to manufacture [`BatchAssociateResourcesToCustomLineItemInput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemInput).
    pub fn builder() -> crate::operation::batch_associate_resources_to_custom_line_item::builders::BatchAssociateResourcesToCustomLineItemInputBuilder
    {
        crate::operation::batch_associate_resources_to_custom_line_item::builders::BatchAssociateResourcesToCustomLineItemInputBuilder::default()
    }
}

/// A builder for [`BatchAssociateResourcesToCustomLineItemInput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchAssociateResourcesToCustomLineItemInputBuilder {
    pub(crate) target_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) billing_period_range: ::std::option::Option<crate::types::CustomLineItemBillingPeriodRange>,
}
impl BatchAssociateResourcesToCustomLineItemInputBuilder {
    /// <p>A percentage custom line item ARN to associate the resources to.</p>
    /// This field is required.
    pub fn target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A percentage custom line item ARN to associate the resources to.</p>
    pub fn set_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_arn = input;
        self
    }
    /// <p>A percentage custom line item ARN to associate the resources to.</p>
    pub fn get_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_arn
    }
    /// Appends an item to `resource_arns`.
    ///
    /// To override the contents of this collection use [`set_resource_arns`](Self::set_resource_arns).
    ///
    /// <p>A list containing the ARNs of the resources to be associated.</p>
    pub fn resource_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_arns.unwrap_or_default();
        v.push(input.into());
        self.resource_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list containing the ARNs of the resources to be associated.</p>
    pub fn set_resource_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_arns = input;
        self
    }
    /// <p>A list containing the ARNs of the resources to be associated.</p>
    pub fn get_resource_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_arns
    }
    /// <p>The billing period range in which the custom line item request will be applied.</p>
    pub fn billing_period_range(mut self, input: crate::types::CustomLineItemBillingPeriodRange) -> Self {
        self.billing_period_range = ::std::option::Option::Some(input);
        self
    }
    /// <p>The billing period range in which the custom line item request will be applied.</p>
    pub fn set_billing_period_range(mut self, input: ::std::option::Option<crate::types::CustomLineItemBillingPeriodRange>) -> Self {
        self.billing_period_range = input;
        self
    }
    /// <p>The billing period range in which the custom line item request will be applied.</p>
    pub fn get_billing_period_range(&self) -> &::std::option::Option<crate::types::CustomLineItemBillingPeriodRange> {
        &self.billing_period_range
    }
    /// Consumes the builder and constructs a [`BatchAssociateResourcesToCustomLineItemInput`](crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::batch_associate_resources_to_custom_line_item::BatchAssociateResourcesToCustomLineItemInput {
                target_arn: self.target_arn,
                resource_arns: self.resource_arns,
                billing_period_range: self.billing_period_range,
            },
        )
    }
}
