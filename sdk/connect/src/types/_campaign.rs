// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information associated with a campaign.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Campaign {
    /// <p>A unique identifier for a campaign.</p>
    pub campaign_id: ::std::option::Option<::std::string::String>,
}
impl Campaign {
    /// <p>A unique identifier for a campaign.</p>
    pub fn campaign_id(&self) -> ::std::option::Option<&str> {
        self.campaign_id.as_deref()
    }
}
impl Campaign {
    /// Creates a new builder-style object to manufacture [`Campaign`](crate::types::Campaign).
    pub fn builder() -> crate::types::builders::CampaignBuilder {
        crate::types::builders::CampaignBuilder::default()
    }
}

/// A builder for [`Campaign`](crate::types::Campaign).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CampaignBuilder {
    pub(crate) campaign_id: ::std::option::Option<::std::string::String>,
}
impl CampaignBuilder {
    /// <p>A unique identifier for a campaign.</p>
    pub fn campaign_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.campaign_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for a campaign.</p>
    pub fn set_campaign_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.campaign_id = input;
        self
    }
    /// <p>A unique identifier for a campaign.</p>
    pub fn get_campaign_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.campaign_id
    }
    /// Consumes the builder and constructs a [`Campaign`](crate::types::Campaign).
    pub fn build(self) -> crate::types::Campaign {
        crate::types::Campaign {
            campaign_id: self.campaign_id,
        }
    }
}
