// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configure a Snowflake VPC</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SnowflakeVpcConfiguration {
    /// <p>The VPCE ID for Firehose to privately connect with Snowflake. The ID format is com.amazonaws.vpce.\[region\].vpce-svc-&lt;\[id\]&gt;. For more information, see Amazon PrivateLink &amp; Snowflake</p>
    pub private_link_vpce_id: ::std::string::String,
}
impl SnowflakeVpcConfiguration {
    /// <p>The VPCE ID for Firehose to privately connect with Snowflake. The ID format is com.amazonaws.vpce.\[region\].vpce-svc-&lt;\[id\]&gt;. For more information, see Amazon PrivateLink &amp; Snowflake</p>
    pub fn private_link_vpce_id(&self) -> &str {
        use std::ops::Deref;
        self.private_link_vpce_id.deref()
    }
}
impl ::std::fmt::Debug for SnowflakeVpcConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SnowflakeVpcConfiguration");
        formatter.field("private_link_vpce_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl SnowflakeVpcConfiguration {
    /// Creates a new builder-style object to manufacture [`SnowflakeVpcConfiguration`](crate::types::SnowflakeVpcConfiguration).
    pub fn builder() -> crate::types::builders::SnowflakeVpcConfigurationBuilder {
        crate::types::builders::SnowflakeVpcConfigurationBuilder::default()
    }
}

/// A builder for [`SnowflakeVpcConfiguration`](crate::types::SnowflakeVpcConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SnowflakeVpcConfigurationBuilder {
    pub(crate) private_link_vpce_id: ::std::option::Option<::std::string::String>,
}
impl SnowflakeVpcConfigurationBuilder {
    /// <p>The VPCE ID for Firehose to privately connect with Snowflake. The ID format is com.amazonaws.vpce.\[region\].vpce-svc-&lt;\[id\]&gt;. For more information, see Amazon PrivateLink &amp; Snowflake</p>
    /// This field is required.
    pub fn private_link_vpce_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.private_link_vpce_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPCE ID for Firehose to privately connect with Snowflake. The ID format is com.amazonaws.vpce.\[region\].vpce-svc-&lt;\[id\]&gt;. For more information, see Amazon PrivateLink &amp; Snowflake</p>
    pub fn set_private_link_vpce_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.private_link_vpce_id = input;
        self
    }
    /// <p>The VPCE ID for Firehose to privately connect with Snowflake. The ID format is com.amazonaws.vpce.\[region\].vpce-svc-&lt;\[id\]&gt;. For more information, see Amazon PrivateLink &amp; Snowflake</p>
    pub fn get_private_link_vpce_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.private_link_vpce_id
    }
    /// Consumes the builder and constructs a [`SnowflakeVpcConfiguration`](crate::types::SnowflakeVpcConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`private_link_vpce_id`](crate::types::builders::SnowflakeVpcConfigurationBuilder::private_link_vpce_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SnowflakeVpcConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SnowflakeVpcConfiguration {
            private_link_vpce_id: self.private_link_vpce_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "private_link_vpce_id",
                    "private_link_vpce_id was not specified but it is required when building SnowflakeVpcConfiguration",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for SnowflakeVpcConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SnowflakeVpcConfigurationBuilder");
        formatter.field("private_link_vpce_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
