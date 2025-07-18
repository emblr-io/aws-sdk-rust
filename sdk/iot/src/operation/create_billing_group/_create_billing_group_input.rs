// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBillingGroupInput {
    /// <p>The name you wish to give to the billing group.</p>
    pub billing_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The properties of the billing group.</p>
    pub billing_group_properties: ::std::option::Option<crate::types::BillingGroupProperties>,
    /// <p>Metadata which can be used to manage the billing group.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateBillingGroupInput {
    /// <p>The name you wish to give to the billing group.</p>
    pub fn billing_group_name(&self) -> ::std::option::Option<&str> {
        self.billing_group_name.as_deref()
    }
    /// <p>The properties of the billing group.</p>
    pub fn billing_group_properties(&self) -> ::std::option::Option<&crate::types::BillingGroupProperties> {
        self.billing_group_properties.as_ref()
    }
    /// <p>Metadata which can be used to manage the billing group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateBillingGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateBillingGroupInput`](crate::operation::create_billing_group::CreateBillingGroupInput).
    pub fn builder() -> crate::operation::create_billing_group::builders::CreateBillingGroupInputBuilder {
        crate::operation::create_billing_group::builders::CreateBillingGroupInputBuilder::default()
    }
}

/// A builder for [`CreateBillingGroupInput`](crate::operation::create_billing_group::CreateBillingGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBillingGroupInputBuilder {
    pub(crate) billing_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) billing_group_properties: ::std::option::Option<crate::types::BillingGroupProperties>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateBillingGroupInputBuilder {
    /// <p>The name you wish to give to the billing group.</p>
    /// This field is required.
    pub fn billing_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.billing_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name you wish to give to the billing group.</p>
    pub fn set_billing_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.billing_group_name = input;
        self
    }
    /// <p>The name you wish to give to the billing group.</p>
    pub fn get_billing_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.billing_group_name
    }
    /// <p>The properties of the billing group.</p>
    pub fn billing_group_properties(mut self, input: crate::types::BillingGroupProperties) -> Self {
        self.billing_group_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The properties of the billing group.</p>
    pub fn set_billing_group_properties(mut self, input: ::std::option::Option<crate::types::BillingGroupProperties>) -> Self {
        self.billing_group_properties = input;
        self
    }
    /// <p>The properties of the billing group.</p>
    pub fn get_billing_group_properties(&self) -> &::std::option::Option<crate::types::BillingGroupProperties> {
        &self.billing_group_properties
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata which can be used to manage the billing group.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata which can be used to manage the billing group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata which can be used to manage the billing group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateBillingGroupInput`](crate::operation::create_billing_group::CreateBillingGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_billing_group::CreateBillingGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_billing_group::CreateBillingGroupInput {
            billing_group_name: self.billing_group_name,
            billing_group_properties: self.billing_group_properties,
            tags: self.tags,
        })
    }
}
