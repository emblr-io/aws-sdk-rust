// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains the type of limit that you specified in the request and the current value for that limit.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HostedZoneLimit {
    /// <p>The limit that you requested. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>MAX_RRSETS_BY_ZONE</b>: The maximum number of records that you can create in the specified hosted zone.</p></li>
    /// <li>
    /// <p><b>MAX_VPCS_ASSOCIATED_BY_ZONE</b>: The maximum number of Amazon VPCs that you can associate with the specified private hosted zone.</p></li>
    /// </ul>
    pub r#type: crate::types::HostedZoneLimitType,
    /// <p>The current value for the limit that is specified by <code>Type</code>.</p>
    pub value: i64,
}
impl HostedZoneLimit {
    /// <p>The limit that you requested. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>MAX_RRSETS_BY_ZONE</b>: The maximum number of records that you can create in the specified hosted zone.</p></li>
    /// <li>
    /// <p><b>MAX_VPCS_ASSOCIATED_BY_ZONE</b>: The maximum number of Amazon VPCs that you can associate with the specified private hosted zone.</p></li>
    /// </ul>
    pub fn r#type(&self) -> &crate::types::HostedZoneLimitType {
        &self.r#type
    }
    /// <p>The current value for the limit that is specified by <code>Type</code>.</p>
    pub fn value(&self) -> i64 {
        self.value
    }
}
impl HostedZoneLimit {
    /// Creates a new builder-style object to manufacture [`HostedZoneLimit`](crate::types::HostedZoneLimit).
    pub fn builder() -> crate::types::builders::HostedZoneLimitBuilder {
        crate::types::builders::HostedZoneLimitBuilder::default()
    }
}

/// A builder for [`HostedZoneLimit`](crate::types::HostedZoneLimit).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HostedZoneLimitBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::HostedZoneLimitType>,
    pub(crate) value: ::std::option::Option<i64>,
}
impl HostedZoneLimitBuilder {
    /// <p>The limit that you requested. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>MAX_RRSETS_BY_ZONE</b>: The maximum number of records that you can create in the specified hosted zone.</p></li>
    /// <li>
    /// <p><b>MAX_VPCS_ASSOCIATED_BY_ZONE</b>: The maximum number of Amazon VPCs that you can associate with the specified private hosted zone.</p></li>
    /// </ul>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::HostedZoneLimitType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit that you requested. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>MAX_RRSETS_BY_ZONE</b>: The maximum number of records that you can create in the specified hosted zone.</p></li>
    /// <li>
    /// <p><b>MAX_VPCS_ASSOCIATED_BY_ZONE</b>: The maximum number of Amazon VPCs that you can associate with the specified private hosted zone.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::HostedZoneLimitType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The limit that you requested. Valid values include the following:</p>
    /// <ul>
    /// <li>
    /// <p><b>MAX_RRSETS_BY_ZONE</b>: The maximum number of records that you can create in the specified hosted zone.</p></li>
    /// <li>
    /// <p><b>MAX_VPCS_ASSOCIATED_BY_ZONE</b>: The maximum number of Amazon VPCs that you can associate with the specified private hosted zone.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::HostedZoneLimitType> {
        &self.r#type
    }
    /// <p>The current value for the limit that is specified by <code>Type</code>.</p>
    /// This field is required.
    pub fn value(mut self, input: i64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current value for the limit that is specified by <code>Type</code>.</p>
    pub fn set_value(mut self, input: ::std::option::Option<i64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The current value for the limit that is specified by <code>Type</code>.</p>
    pub fn get_value(&self) -> &::std::option::Option<i64> {
        &self.value
    }
    /// Consumes the builder and constructs a [`HostedZoneLimit`](crate::types::HostedZoneLimit).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::HostedZoneLimitBuilder::type)
    /// - [`value`](crate::types::builders::HostedZoneLimitBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::HostedZoneLimit, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::HostedZoneLimit {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building HostedZoneLimit",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building HostedZoneLimit",
                )
            })?,
        })
    }
}
