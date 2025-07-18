// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains the configuration for how an app monitor can unminify JavaScript error stack traces using source maps.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JavaScriptSourceMaps {
    /// <p>Specifies whether JavaScript error stack traces should be unminified for this app monitor. The default is for JavaScript error stack trace unminification to be <code>DISABLED</code>.</p>
    pub status: crate::types::DeobfuscationStatus,
    /// <p>The S3Uri of the bucket or folder that stores the source map files. It is required if status is ENABLED.</p>
    pub s3_uri: ::std::option::Option<::std::string::String>,
}
impl JavaScriptSourceMaps {
    /// <p>Specifies whether JavaScript error stack traces should be unminified for this app monitor. The default is for JavaScript error stack trace unminification to be <code>DISABLED</code>.</p>
    pub fn status(&self) -> &crate::types::DeobfuscationStatus {
        &self.status
    }
    /// <p>The S3Uri of the bucket or folder that stores the source map files. It is required if status is ENABLED.</p>
    pub fn s3_uri(&self) -> ::std::option::Option<&str> {
        self.s3_uri.as_deref()
    }
}
impl JavaScriptSourceMaps {
    /// Creates a new builder-style object to manufacture [`JavaScriptSourceMaps`](crate::types::JavaScriptSourceMaps).
    pub fn builder() -> crate::types::builders::JavaScriptSourceMapsBuilder {
        crate::types::builders::JavaScriptSourceMapsBuilder::default()
    }
}

/// A builder for [`JavaScriptSourceMaps`](crate::types::JavaScriptSourceMaps).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JavaScriptSourceMapsBuilder {
    pub(crate) status: ::std::option::Option<crate::types::DeobfuscationStatus>,
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
}
impl JavaScriptSourceMapsBuilder {
    /// <p>Specifies whether JavaScript error stack traces should be unminified for this app monitor. The default is for JavaScript error stack trace unminification to be <code>DISABLED</code>.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::DeobfuscationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether JavaScript error stack traces should be unminified for this app monitor. The default is for JavaScript error stack trace unminification to be <code>DISABLED</code>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DeobfuscationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies whether JavaScript error stack traces should be unminified for this app monitor. The default is for JavaScript error stack trace unminification to be <code>DISABLED</code>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DeobfuscationStatus> {
        &self.status
    }
    /// <p>The S3Uri of the bucket or folder that stores the source map files. It is required if status is ENABLED.</p>
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3Uri of the bucket or folder that stores the source map files. It is required if status is ENABLED.</p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The S3Uri of the bucket or folder that stores the source map files. It is required if status is ENABLED.</p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// Consumes the builder and constructs a [`JavaScriptSourceMaps`](crate::types::JavaScriptSourceMaps).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::types::builders::JavaScriptSourceMapsBuilder::status)
    pub fn build(self) -> ::std::result::Result<crate::types::JavaScriptSourceMaps, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::JavaScriptSourceMaps {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building JavaScriptSourceMaps",
                )
            })?,
            s3_uri: self.s3_uri,
        })
    }
}
