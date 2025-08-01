// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// The request for DescribeCampaign API.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCampaignInput {
    /// Identifier representing a Campaign
    pub id: ::std::option::Option<::std::string::String>,
}
impl DescribeCampaignInput {
    /// Identifier representing a Campaign
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl DescribeCampaignInput {
    /// Creates a new builder-style object to manufacture [`DescribeCampaignInput`](crate::operation::describe_campaign::DescribeCampaignInput).
    pub fn builder() -> crate::operation::describe_campaign::builders::DescribeCampaignInputBuilder {
        crate::operation::describe_campaign::builders::DescribeCampaignInputBuilder::default()
    }
}

/// A builder for [`DescribeCampaignInput`](crate::operation::describe_campaign::DescribeCampaignInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCampaignInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl DescribeCampaignInputBuilder {
    /// Identifier representing a Campaign
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// Identifier representing a Campaign
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// Identifier representing a Campaign
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`DescribeCampaignInput`](crate::operation::describe_campaign::DescribeCampaignInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_campaign::DescribeCampaignInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_campaign::DescribeCampaignInput { id: self.id })
    }
}
