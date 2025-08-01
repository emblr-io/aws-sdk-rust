// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportLensInput {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub lens_alias: ::std::option::Option<::std::string::String>,
    /// <p>The lens version to be exported.</p>
    pub lens_version: ::std::option::Option<::std::string::String>,
}
impl ExportLensInput {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn lens_alias(&self) -> ::std::option::Option<&str> {
        self.lens_alias.as_deref()
    }
    /// <p>The lens version to be exported.</p>
    pub fn lens_version(&self) -> ::std::option::Option<&str> {
        self.lens_version.as_deref()
    }
}
impl ExportLensInput {
    /// Creates a new builder-style object to manufacture [`ExportLensInput`](crate::operation::export_lens::ExportLensInput).
    pub fn builder() -> crate::operation::export_lens::builders::ExportLensInputBuilder {
        crate::operation::export_lens::builders::ExportLensInputBuilder::default()
    }
}

/// A builder for [`ExportLensInput`](crate::operation::export_lens::ExportLensInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportLensInputBuilder {
    pub(crate) lens_alias: ::std::option::Option<::std::string::String>,
    pub(crate) lens_version: ::std::option::Option<::std::string::String>,
}
impl ExportLensInputBuilder {
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    /// This field is required.
    pub fn lens_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn set_lens_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_alias = input;
        self
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn get_lens_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_alias
    }
    /// <p>The lens version to be exported.</p>
    pub fn lens_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The lens version to be exported.</p>
    pub fn set_lens_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_version = input;
        self
    }
    /// <p>The lens version to be exported.</p>
    pub fn get_lens_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_version
    }
    /// Consumes the builder and constructs a [`ExportLensInput`](crate::operation::export_lens::ExportLensInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::export_lens::ExportLensInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::export_lens::ExportLensInput {
            lens_alias: self.lens_alias,
            lens_version: self.lens_version,
        })
    }
}
