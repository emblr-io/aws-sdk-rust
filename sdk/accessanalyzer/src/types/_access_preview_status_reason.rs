// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides more details about the current status of the access preview. For example, if the creation of the access preview fails, a <code>Failed</code> status is returned. This failure can be due to an internal issue with the analysis or due to an invalid proposed resource configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccessPreviewStatusReason {
    /// <p>The reason code for the current status of the access preview.</p>
    pub code: crate::types::AccessPreviewStatusReasonCode,
}
impl AccessPreviewStatusReason {
    /// <p>The reason code for the current status of the access preview.</p>
    pub fn code(&self) -> &crate::types::AccessPreviewStatusReasonCode {
        &self.code
    }
}
impl AccessPreviewStatusReason {
    /// Creates a new builder-style object to manufacture [`AccessPreviewStatusReason`](crate::types::AccessPreviewStatusReason).
    pub fn builder() -> crate::types::builders::AccessPreviewStatusReasonBuilder {
        crate::types::builders::AccessPreviewStatusReasonBuilder::default()
    }
}

/// A builder for [`AccessPreviewStatusReason`](crate::types::AccessPreviewStatusReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccessPreviewStatusReasonBuilder {
    pub(crate) code: ::std::option::Option<crate::types::AccessPreviewStatusReasonCode>,
}
impl AccessPreviewStatusReasonBuilder {
    /// <p>The reason code for the current status of the access preview.</p>
    /// This field is required.
    pub fn code(mut self, input: crate::types::AccessPreviewStatusReasonCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason code for the current status of the access preview.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::AccessPreviewStatusReasonCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The reason code for the current status of the access preview.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::AccessPreviewStatusReasonCode> {
        &self.code
    }
    /// Consumes the builder and constructs a [`AccessPreviewStatusReason`](crate::types::AccessPreviewStatusReason).
    /// This method will fail if any of the following fields are not set:
    /// - [`code`](crate::types::builders::AccessPreviewStatusReasonBuilder::code)
    pub fn build(self) -> ::std::result::Result<crate::types::AccessPreviewStatusReason, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AccessPreviewStatusReason {
            code: self.code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code",
                    "code was not specified but it is required when building AccessPreviewStatusReason",
                )
            })?,
        })
    }
}
