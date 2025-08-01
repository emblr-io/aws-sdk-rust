// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A read-only field that represents the state of an <code>AppInstanceUserEndpoint</code>. Supported values:</p>
/// <ul>
/// <li>
/// <p><code>ACTIVE</code>: The <code>AppInstanceUserEndpoint</code> is active and able to receive messages. When <code>ACTIVE</code>, the <code>EndpointStatusReason</code> remains empty.</p></li>
/// <li>
/// <p><code>INACTIVE</code>: The <code>AppInstanceUserEndpoint</code> is inactive and can't receive message. When INACTIVE, the corresponding reason will be conveyed through EndpointStatusReason.</p></li>
/// <li>
/// <p><code>INVALID_DEVICE_TOKEN</code> indicates that an <code>AppInstanceUserEndpoint</code> is <code>INACTIVE</code> due to invalid device token</p></li>
/// <li>
/// <p><code>INVALID_PINPOINT_ARN</code> indicates that an <code>AppInstanceUserEndpoint</code> is <code>INACTIVE</code> due to an invalid pinpoint ARN that was input through the <code>ResourceArn</code> field.</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EndpointState {
    /// <p>Enum that indicates the Status of an <code>AppInstanceUserEndpoint</code>.</p>
    pub status: crate::types::EndpointStatus,
    /// <p>The reason for the <code>EndpointStatus</code>.</p>
    pub status_reason: ::std::option::Option<crate::types::EndpointStatusReason>,
}
impl EndpointState {
    /// <p>Enum that indicates the Status of an <code>AppInstanceUserEndpoint</code>.</p>
    pub fn status(&self) -> &crate::types::EndpointStatus {
        &self.status
    }
    /// <p>The reason for the <code>EndpointStatus</code>.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&crate::types::EndpointStatusReason> {
        self.status_reason.as_ref()
    }
}
impl EndpointState {
    /// Creates a new builder-style object to manufacture [`EndpointState`](crate::types::EndpointState).
    pub fn builder() -> crate::types::builders::EndpointStateBuilder {
        crate::types::builders::EndpointStateBuilder::default()
    }
}

/// A builder for [`EndpointState`](crate::types::EndpointState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EndpointStateBuilder {
    pub(crate) status: ::std::option::Option<crate::types::EndpointStatus>,
    pub(crate) status_reason: ::std::option::Option<crate::types::EndpointStatusReason>,
}
impl EndpointStateBuilder {
    /// <p>Enum that indicates the Status of an <code>AppInstanceUserEndpoint</code>.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::EndpointStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enum that indicates the Status of an <code>AppInstanceUserEndpoint</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::EndpointStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Enum that indicates the Status of an <code>AppInstanceUserEndpoint</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::EndpointStatus> {
        &self.status
    }
    /// <p>The reason for the <code>EndpointStatus</code>.</p>
    pub fn status_reason(mut self, input: crate::types::EndpointStatusReason) -> Self {
        self.status_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason for the <code>EndpointStatus</code>.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<crate::types::EndpointStatusReason>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The reason for the <code>EndpointStatus</code>.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<crate::types::EndpointStatusReason> {
        &self.status_reason
    }
    /// Consumes the builder and constructs a [`EndpointState`](crate::types::EndpointState).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::EndpointStateBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::EndpointState, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EndpointState {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building EndpointState",
                )
            })?,
            status_reason: self.status_reason,
        })
    }
}
