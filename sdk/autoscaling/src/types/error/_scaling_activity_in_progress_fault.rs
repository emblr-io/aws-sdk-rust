// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The operation can't be performed because there are scaling activities in progress.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScalingActivityInProgressFault {
    /// <p></p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ScalingActivityInProgressFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for ScalingActivityInProgressFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ScalingActivityInProgressFault")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for ScalingActivityInProgressFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::ScalingActivityInProgressFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ScalingActivityInProgressFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ScalingActivityInProgressFault {
    /// Creates a new builder-style object to manufacture [`ScalingActivityInProgressFault`](crate::types::error::ScalingActivityInProgressFault).
    pub fn builder() -> crate::types::error::builders::ScalingActivityInProgressFaultBuilder {
        crate::types::error::builders::ScalingActivityInProgressFaultBuilder::default()
    }
}

/// A builder for [`ScalingActivityInProgressFault`](crate::types::error::ScalingActivityInProgressFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScalingActivityInProgressFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ScalingActivityInProgressFaultBuilder {
    /// <p></p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p></p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p></p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Sets error metadata
    pub fn meta(mut self, meta: ::aws_smithy_types::error::ErrorMetadata) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Sets error metadata
    pub fn set_meta(&mut self, meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>) -> &mut Self {
        self.meta = meta;
        self
    }
    /// Consumes the builder and constructs a [`ScalingActivityInProgressFault`](crate::types::error::ScalingActivityInProgressFault).
    pub fn build(self) -> crate::types::error::ScalingActivityInProgressFault {
        crate::types::error::ScalingActivityInProgressFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
