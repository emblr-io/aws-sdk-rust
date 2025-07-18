// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A lens summary of a lens.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LensSummary {
    /// <p>The ARN of the lens.</p>
    pub lens_arn: ::std::option::Option<::std::string::String>,
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub lens_alias: ::std::option::Option<::std::string::String>,
    /// <p>The full name of the lens.</p>
    pub lens_name: ::std::option::Option<::std::string::String>,
    /// <p>The type of the lens.</p>
    pub lens_type: ::std::option::Option<crate::types::LensType>,
    /// <p>The description of the lens.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The date and time recorded.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time recorded.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The version of the lens.</p>
    pub lens_version: ::std::option::Option<::std::string::String>,
    /// <p>An Amazon Web Services account ID.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The status of the lens.</p>
    pub lens_status: ::std::option::Option<crate::types::LensStatus>,
}
impl LensSummary {
    /// <p>The ARN of the lens.</p>
    pub fn lens_arn(&self) -> ::std::option::Option<&str> {
        self.lens_arn.as_deref()
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
    pub fn lens_alias(&self) -> ::std::option::Option<&str> {
        self.lens_alias.as_deref()
    }
    /// <p>The full name of the lens.</p>
    pub fn lens_name(&self) -> ::std::option::Option<&str> {
        self.lens_name.as_deref()
    }
    /// <p>The type of the lens.</p>
    pub fn lens_type(&self) -> ::std::option::Option<&crate::types::LensType> {
        self.lens_type.as_ref()
    }
    /// <p>The description of the lens.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The date and time recorded.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time recorded.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The version of the lens.</p>
    pub fn lens_version(&self) -> ::std::option::Option<&str> {
        self.lens_version.as_deref()
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The status of the lens.</p>
    pub fn lens_status(&self) -> ::std::option::Option<&crate::types::LensStatus> {
        self.lens_status.as_ref()
    }
}
impl LensSummary {
    /// Creates a new builder-style object to manufacture [`LensSummary`](crate::types::LensSummary).
    pub fn builder() -> crate::types::builders::LensSummaryBuilder {
        crate::types::builders::LensSummaryBuilder::default()
    }
}

/// A builder for [`LensSummary`](crate::types::LensSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LensSummaryBuilder {
    pub(crate) lens_arn: ::std::option::Option<::std::string::String>,
    pub(crate) lens_alias: ::std::option::Option<::std::string::String>,
    pub(crate) lens_name: ::std::option::Option<::std::string::String>,
    pub(crate) lens_type: ::std::option::Option<crate::types::LensType>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) lens_version: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) lens_status: ::std::option::Option<crate::types::LensStatus>,
}
impl LensSummaryBuilder {
    /// <p>The ARN of the lens.</p>
    pub fn lens_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the lens.</p>
    pub fn set_lens_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_arn = input;
        self
    }
    /// <p>The ARN of the lens.</p>
    pub fn get_lens_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_arn
    }
    /// <p>The alias of the lens.</p>
    /// <p>For Amazon Web Services official lenses, this is either the lens alias, such as <code>serverless</code>, or the lens ARN, such as <code>arn:aws:wellarchitected:us-east-1::lens/serverless</code>. Note that some operations (such as ExportLens and CreateLensShare) are not permitted on Amazon Web Services official lenses.</p>
    /// <p>For custom lenses, this is the lens ARN, such as <code>arn:aws:wellarchitected:us-west-2:123456789012:lens/0123456789abcdef01234567890abcdef</code>.</p>
    /// <p>Each lens is identified by its <code>LensSummary$LensAlias</code>.</p>
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
    /// <p>The full name of the lens.</p>
    pub fn lens_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full name of the lens.</p>
    pub fn set_lens_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_name = input;
        self
    }
    /// <p>The full name of the lens.</p>
    pub fn get_lens_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_name
    }
    /// <p>The type of the lens.</p>
    pub fn lens_type(mut self, input: crate::types::LensType) -> Self {
        self.lens_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the lens.</p>
    pub fn set_lens_type(mut self, input: ::std::option::Option<crate::types::LensType>) -> Self {
        self.lens_type = input;
        self
    }
    /// <p>The type of the lens.</p>
    pub fn get_lens_type(&self) -> &::std::option::Option<crate::types::LensType> {
        &self.lens_type
    }
    /// <p>The description of the lens.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the lens.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the lens.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The date and time recorded.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time recorded.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time recorded.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The version of the lens.</p>
    pub fn lens_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lens_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the lens.</p>
    pub fn set_lens_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lens_version = input;
        self
    }
    /// <p>The version of the lens.</p>
    pub fn get_lens_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.lens_version
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>An Amazon Web Services account ID.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The status of the lens.</p>
    pub fn lens_status(mut self, input: crate::types::LensStatus) -> Self {
        self.lens_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the lens.</p>
    pub fn set_lens_status(mut self, input: ::std::option::Option<crate::types::LensStatus>) -> Self {
        self.lens_status = input;
        self
    }
    /// <p>The status of the lens.</p>
    pub fn get_lens_status(&self) -> &::std::option::Option<crate::types::LensStatus> {
        &self.lens_status
    }
    /// Consumes the builder and constructs a [`LensSummary`](crate::types::LensSummary).
    pub fn build(self) -> crate::types::LensSummary {
        crate::types::LensSummary {
            lens_arn: self.lens_arn,
            lens_alias: self.lens_alias,
            lens_name: self.lens_name,
            lens_type: self.lens_type,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
            lens_version: self.lens_version,
            owner: self.owner,
            lens_status: self.lens_status,
        }
    }
}
