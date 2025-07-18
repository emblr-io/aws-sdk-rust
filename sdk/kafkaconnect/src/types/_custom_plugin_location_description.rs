// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the location of a custom plugin.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomPluginLocationDescription {
    /// <p>The S3 bucket Amazon Resource Name (ARN), file key, and object version of the plugin file stored in Amazon S3.</p>
    pub s3_location: ::std::option::Option<crate::types::S3LocationDescription>,
}
impl CustomPluginLocationDescription {
    /// <p>The S3 bucket Amazon Resource Name (ARN), file key, and object version of the plugin file stored in Amazon S3.</p>
    pub fn s3_location(&self) -> ::std::option::Option<&crate::types::S3LocationDescription> {
        self.s3_location.as_ref()
    }
}
impl CustomPluginLocationDescription {
    /// Creates a new builder-style object to manufacture [`CustomPluginLocationDescription`](crate::types::CustomPluginLocationDescription).
    pub fn builder() -> crate::types::builders::CustomPluginLocationDescriptionBuilder {
        crate::types::builders::CustomPluginLocationDescriptionBuilder::default()
    }
}

/// A builder for [`CustomPluginLocationDescription`](crate::types::CustomPluginLocationDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomPluginLocationDescriptionBuilder {
    pub(crate) s3_location: ::std::option::Option<crate::types::S3LocationDescription>,
}
impl CustomPluginLocationDescriptionBuilder {
    /// <p>The S3 bucket Amazon Resource Name (ARN), file key, and object version of the plugin file stored in Amazon S3.</p>
    pub fn s3_location(mut self, input: crate::types::S3LocationDescription) -> Self {
        self.s3_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The S3 bucket Amazon Resource Name (ARN), file key, and object version of the plugin file stored in Amazon S3.</p>
    pub fn set_s3_location(mut self, input: ::std::option::Option<crate::types::S3LocationDescription>) -> Self {
        self.s3_location = input;
        self
    }
    /// <p>The S3 bucket Amazon Resource Name (ARN), file key, and object version of the plugin file stored in Amazon S3.</p>
    pub fn get_s3_location(&self) -> &::std::option::Option<crate::types::S3LocationDescription> {
        &self.s3_location
    }
    /// Consumes the builder and constructs a [`CustomPluginLocationDescription`](crate::types::CustomPluginLocationDescription).
    pub fn build(self) -> crate::types::CustomPluginLocationDescription {
        crate::types::CustomPluginLocationDescription {
            s3_location: self.s3_location,
        }
    }
}
