// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This object defines one value to be copied with the <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation.html#CloudWatch-Logs-Transformation-copoyValue"> copyValue</a> processor.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyValueEntry {
    /// <p>The key to copy.</p>
    pub source: ::std::string::String,
    /// <p>The key of the field to copy the value to.</p>
    pub target: ::std::string::String,
    /// <p>Specifies whether to overwrite the value if the destination key already exists. If you omit this, the default is <code>false</code>.</p>
    pub overwrite_if_exists: bool,
}
impl CopyValueEntry {
    /// <p>The key to copy.</p>
    pub fn source(&self) -> &str {
        use std::ops::Deref;
        self.source.deref()
    }
    /// <p>The key of the field to copy the value to.</p>
    pub fn target(&self) -> &str {
        use std::ops::Deref;
        self.target.deref()
    }
    /// <p>Specifies whether to overwrite the value if the destination key already exists. If you omit this, the default is <code>false</code>.</p>
    pub fn overwrite_if_exists(&self) -> bool {
        self.overwrite_if_exists
    }
}
impl CopyValueEntry {
    /// Creates a new builder-style object to manufacture [`CopyValueEntry`](crate::types::CopyValueEntry).
    pub fn builder() -> crate::types::builders::CopyValueEntryBuilder {
        crate::types::builders::CopyValueEntryBuilder::default()
    }
}

/// A builder for [`CopyValueEntry`](crate::types::CopyValueEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyValueEntryBuilder {
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) target: ::std::option::Option<::std::string::String>,
    pub(crate) overwrite_if_exists: ::std::option::Option<bool>,
}
impl CopyValueEntryBuilder {
    /// <p>The key to copy.</p>
    /// This field is required.
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key to copy.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>The key to copy.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>The key of the field to copy the value to.</p>
    /// This field is required.
    pub fn target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key of the field to copy the value to.</p>
    pub fn set_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target = input;
        self
    }
    /// <p>The key of the field to copy the value to.</p>
    pub fn get_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.target
    }
    /// <p>Specifies whether to overwrite the value if the destination key already exists. If you omit this, the default is <code>false</code>.</p>
    pub fn overwrite_if_exists(mut self, input: bool) -> Self {
        self.overwrite_if_exists = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to overwrite the value if the destination key already exists. If you omit this, the default is <code>false</code>.</p>
    pub fn set_overwrite_if_exists(mut self, input: ::std::option::Option<bool>) -> Self {
        self.overwrite_if_exists = input;
        self
    }
    /// <p>Specifies whether to overwrite the value if the destination key already exists. If you omit this, the default is <code>false</code>.</p>
    pub fn get_overwrite_if_exists(&self) -> &::std::option::Option<bool> {
        &self.overwrite_if_exists
    }
    /// Consumes the builder and constructs a [`CopyValueEntry`](crate::types::CopyValueEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`source`](crate::types::builders::CopyValueEntryBuilder::source)
    /// - [`target`](crate::types::builders::CopyValueEntryBuilder::target)
    pub fn build(self) -> ::std::result::Result<crate::types::CopyValueEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CopyValueEntry {
            source: self.source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source",
                    "source was not specified but it is required when building CopyValueEntry",
                )
            })?,
            target: self.target.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "target",
                    "target was not specified but it is required when building CopyValueEntry",
                )
            })?,
            overwrite_if_exists: self.overwrite_if_exists.unwrap_or_default(),
        })
    }
}
