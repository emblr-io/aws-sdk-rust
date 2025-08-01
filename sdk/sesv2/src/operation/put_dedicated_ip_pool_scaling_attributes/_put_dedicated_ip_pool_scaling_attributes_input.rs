// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to convert a dedicated IP pool to a different scaling mode.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutDedicatedIpPoolScalingAttributesInput {
    /// <p>The name of the dedicated IP pool.</p>
    pub pool_name: ::std::option::Option<::std::string::String>,
    /// <p>The scaling mode to apply to the dedicated IP pool.</p><note>
    /// <p>Changing the scaling mode from <code>MANAGED</code> to <code>STANDARD</code> is not supported.</p>
    /// </note>
    pub scaling_mode: ::std::option::Option<crate::types::ScalingMode>,
}
impl PutDedicatedIpPoolScalingAttributesInput {
    /// <p>The name of the dedicated IP pool.</p>
    pub fn pool_name(&self) -> ::std::option::Option<&str> {
        self.pool_name.as_deref()
    }
    /// <p>The scaling mode to apply to the dedicated IP pool.</p><note>
    /// <p>Changing the scaling mode from <code>MANAGED</code> to <code>STANDARD</code> is not supported.</p>
    /// </note>
    pub fn scaling_mode(&self) -> ::std::option::Option<&crate::types::ScalingMode> {
        self.scaling_mode.as_ref()
    }
}
impl PutDedicatedIpPoolScalingAttributesInput {
    /// Creates a new builder-style object to manufacture [`PutDedicatedIpPoolScalingAttributesInput`](crate::operation::put_dedicated_ip_pool_scaling_attributes::PutDedicatedIpPoolScalingAttributesInput).
    pub fn builder() -> crate::operation::put_dedicated_ip_pool_scaling_attributes::builders::PutDedicatedIpPoolScalingAttributesInputBuilder {
        crate::operation::put_dedicated_ip_pool_scaling_attributes::builders::PutDedicatedIpPoolScalingAttributesInputBuilder::default()
    }
}

/// A builder for [`PutDedicatedIpPoolScalingAttributesInput`](crate::operation::put_dedicated_ip_pool_scaling_attributes::PutDedicatedIpPoolScalingAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutDedicatedIpPoolScalingAttributesInputBuilder {
    pub(crate) pool_name: ::std::option::Option<::std::string::String>,
    pub(crate) scaling_mode: ::std::option::Option<crate::types::ScalingMode>,
}
impl PutDedicatedIpPoolScalingAttributesInputBuilder {
    /// <p>The name of the dedicated IP pool.</p>
    /// This field is required.
    pub fn pool_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dedicated IP pool.</p>
    pub fn set_pool_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_name = input;
        self
    }
    /// <p>The name of the dedicated IP pool.</p>
    pub fn get_pool_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_name
    }
    /// <p>The scaling mode to apply to the dedicated IP pool.</p><note>
    /// <p>Changing the scaling mode from <code>MANAGED</code> to <code>STANDARD</code> is not supported.</p>
    /// </note>
    /// This field is required.
    pub fn scaling_mode(mut self, input: crate::types::ScalingMode) -> Self {
        self.scaling_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scaling mode to apply to the dedicated IP pool.</p><note>
    /// <p>Changing the scaling mode from <code>MANAGED</code> to <code>STANDARD</code> is not supported.</p>
    /// </note>
    pub fn set_scaling_mode(mut self, input: ::std::option::Option<crate::types::ScalingMode>) -> Self {
        self.scaling_mode = input;
        self
    }
    /// <p>The scaling mode to apply to the dedicated IP pool.</p><note>
    /// <p>Changing the scaling mode from <code>MANAGED</code> to <code>STANDARD</code> is not supported.</p>
    /// </note>
    pub fn get_scaling_mode(&self) -> &::std::option::Option<crate::types::ScalingMode> {
        &self.scaling_mode
    }
    /// Consumes the builder and constructs a [`PutDedicatedIpPoolScalingAttributesInput`](crate::operation::put_dedicated_ip_pool_scaling_attributes::PutDedicatedIpPoolScalingAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_dedicated_ip_pool_scaling_attributes::PutDedicatedIpPoolScalingAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_dedicated_ip_pool_scaling_attributes::PutDedicatedIpPoolScalingAttributesInput {
                pool_name: self.pool_name,
                scaling_mode: self.scaling_mode,
            },
        )
    }
}
