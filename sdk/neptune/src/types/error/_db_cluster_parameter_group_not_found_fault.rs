// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p><i>DBClusterParameterGroupName</i> does not refer to an existing DB Cluster parameter group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DbClusterParameterGroupNotFoundFault {
    /// <p>A message describing the details of the problem.</p>
    pub message: ::std::option::Option<::std::string::String>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl DbClusterParameterGroupNotFoundFault {
    /// Returns the error message.
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ::std::fmt::Display for DbClusterParameterGroupNotFoundFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "DbClusterParameterGroupNotFoundFault [DBClusterParameterGroupNotFoundFault]")?;
        if let ::std::option::Option::Some(inner_1) = &self.message {
            {
                ::std::write!(f, ": {}", inner_1)?;
            }
        }
        Ok(())
    }
}
impl ::std::error::Error for DbClusterParameterGroupNotFoundFault {}
impl ::aws_types::request_id::RequestId for crate::types::error::DbClusterParameterGroupNotFoundFault {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for DbClusterParameterGroupNotFoundFault {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl DbClusterParameterGroupNotFoundFault {
    /// Creates a new builder-style object to manufacture [`DbClusterParameterGroupNotFoundFault`](crate::types::error::DbClusterParameterGroupNotFoundFault).
    pub fn builder() -> crate::types::error::builders::DbClusterParameterGroupNotFoundFaultBuilder {
        crate::types::error::builders::DbClusterParameterGroupNotFoundFaultBuilder::default()
    }
}

/// A builder for [`DbClusterParameterGroupNotFoundFault`](crate::types::error::DbClusterParameterGroupNotFoundFault).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DbClusterParameterGroupNotFoundFaultBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl DbClusterParameterGroupNotFoundFaultBuilder {
    /// <p>A message describing the details of the problem.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message describing the details of the problem.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message describing the details of the problem.</p>
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
    /// Consumes the builder and constructs a [`DbClusterParameterGroupNotFoundFault`](crate::types::error::DbClusterParameterGroupNotFoundFault).
    pub fn build(self) -> crate::types::error::DbClusterParameterGroupNotFoundFault {
        crate::types::error::DbClusterParameterGroupNotFoundFault {
            message: self.message,
            meta: self.meta.unwrap_or_default(),
        }
    }
}
