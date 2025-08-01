// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The market (purchasing) option for the instances.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchTemplateInstanceMarketOptionsRequest {
    /// <p>The market type.</p>
    pub market_type: ::std::option::Option<crate::types::MarketType>,
    /// <p>The options for Spot Instances.</p>
    pub spot_options: ::std::option::Option<crate::types::LaunchTemplateSpotMarketOptionsRequest>,
}
impl LaunchTemplateInstanceMarketOptionsRequest {
    /// <p>The market type.</p>
    pub fn market_type(&self) -> ::std::option::Option<&crate::types::MarketType> {
        self.market_type.as_ref()
    }
    /// <p>The options for Spot Instances.</p>
    pub fn spot_options(&self) -> ::std::option::Option<&crate::types::LaunchTemplateSpotMarketOptionsRequest> {
        self.spot_options.as_ref()
    }
}
impl LaunchTemplateInstanceMarketOptionsRequest {
    /// Creates a new builder-style object to manufacture [`LaunchTemplateInstanceMarketOptionsRequest`](crate::types::LaunchTemplateInstanceMarketOptionsRequest).
    pub fn builder() -> crate::types::builders::LaunchTemplateInstanceMarketOptionsRequestBuilder {
        crate::types::builders::LaunchTemplateInstanceMarketOptionsRequestBuilder::default()
    }
}

/// A builder for [`LaunchTemplateInstanceMarketOptionsRequest`](crate::types::LaunchTemplateInstanceMarketOptionsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchTemplateInstanceMarketOptionsRequestBuilder {
    pub(crate) market_type: ::std::option::Option<crate::types::MarketType>,
    pub(crate) spot_options: ::std::option::Option<crate::types::LaunchTemplateSpotMarketOptionsRequest>,
}
impl LaunchTemplateInstanceMarketOptionsRequestBuilder {
    /// <p>The market type.</p>
    pub fn market_type(mut self, input: crate::types::MarketType) -> Self {
        self.market_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The market type.</p>
    pub fn set_market_type(mut self, input: ::std::option::Option<crate::types::MarketType>) -> Self {
        self.market_type = input;
        self
    }
    /// <p>The market type.</p>
    pub fn get_market_type(&self) -> &::std::option::Option<crate::types::MarketType> {
        &self.market_type
    }
    /// <p>The options for Spot Instances.</p>
    pub fn spot_options(mut self, input: crate::types::LaunchTemplateSpotMarketOptionsRequest) -> Self {
        self.spot_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The options for Spot Instances.</p>
    pub fn set_spot_options(mut self, input: ::std::option::Option<crate::types::LaunchTemplateSpotMarketOptionsRequest>) -> Self {
        self.spot_options = input;
        self
    }
    /// <p>The options for Spot Instances.</p>
    pub fn get_spot_options(&self) -> &::std::option::Option<crate::types::LaunchTemplateSpotMarketOptionsRequest> {
        &self.spot_options
    }
    /// Consumes the builder and constructs a [`LaunchTemplateInstanceMarketOptionsRequest`](crate::types::LaunchTemplateInstanceMarketOptionsRequest).
    pub fn build(self) -> crate::types::LaunchTemplateInstanceMarketOptionsRequest {
        crate::types::LaunchTemplateInstanceMarketOptionsRequest {
            market_type: self.market_type,
            spot_options: self.spot_options,
        }
    }
}
