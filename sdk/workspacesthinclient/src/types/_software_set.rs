// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a software set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SoftwareSet {
    /// <p>The ID of the software set.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the software set.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the software set was released.</p>
    pub released_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp of the end of support for the software set.</p>
    pub supported_until: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>An option to define if the software set has been validated.</p>
    pub validation_status: ::std::option::Option<crate::types::SoftwareSetValidationStatus>,
    /// <p>A list of the software components in the software set.</p>
    pub software: ::std::option::Option<::std::vec::Vec<crate::types::Software>>,
    /// <p>The Amazon Resource Name (ARN) of the software set.</p>
    pub arn: ::std::option::Option<::std::string::String>,
}
impl SoftwareSet {
    /// <p>The ID of the software set.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The version of the software set.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The timestamp of when the software set was released.</p>
    pub fn released_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.released_at.as_ref()
    }
    /// <p>The timestamp of the end of support for the software set.</p>
    pub fn supported_until(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.supported_until.as_ref()
    }
    /// <p>An option to define if the software set has been validated.</p>
    pub fn validation_status(&self) -> ::std::option::Option<&crate::types::SoftwareSetValidationStatus> {
        self.validation_status.as_ref()
    }
    /// <p>A list of the software components in the software set.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.software.is_none()`.
    pub fn software(&self) -> &[crate::types::Software] {
        self.software.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of the software set.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
}
impl SoftwareSet {
    /// Creates a new builder-style object to manufacture [`SoftwareSet`](crate::types::SoftwareSet).
    pub fn builder() -> crate::types::builders::SoftwareSetBuilder {
        crate::types::builders::SoftwareSetBuilder::default()
    }
}

/// A builder for [`SoftwareSet`](crate::types::SoftwareSet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SoftwareSetBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) released_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) supported_until: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) validation_status: ::std::option::Option<crate::types::SoftwareSetValidationStatus>,
    pub(crate) software: ::std::option::Option<::std::vec::Vec<crate::types::Software>>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
}
impl SoftwareSetBuilder {
    /// <p>The ID of the software set.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the software set.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the software set.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The version of the software set.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the software set.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the software set.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The timestamp of when the software set was released.</p>
    pub fn released_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.released_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the software set was released.</p>
    pub fn set_released_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.released_at = input;
        self
    }
    /// <p>The timestamp of when the software set was released.</p>
    pub fn get_released_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.released_at
    }
    /// <p>The timestamp of the end of support for the software set.</p>
    pub fn supported_until(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.supported_until = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of the end of support for the software set.</p>
    pub fn set_supported_until(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.supported_until = input;
        self
    }
    /// <p>The timestamp of the end of support for the software set.</p>
    pub fn get_supported_until(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.supported_until
    }
    /// <p>An option to define if the software set has been validated.</p>
    pub fn validation_status(mut self, input: crate::types::SoftwareSetValidationStatus) -> Self {
        self.validation_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>An option to define if the software set has been validated.</p>
    pub fn set_validation_status(mut self, input: ::std::option::Option<crate::types::SoftwareSetValidationStatus>) -> Self {
        self.validation_status = input;
        self
    }
    /// <p>An option to define if the software set has been validated.</p>
    pub fn get_validation_status(&self) -> &::std::option::Option<crate::types::SoftwareSetValidationStatus> {
        &self.validation_status
    }
    /// Appends an item to `software`.
    ///
    /// To override the contents of this collection use [`set_software`](Self::set_software).
    ///
    /// <p>A list of the software components in the software set.</p>
    pub fn software(mut self, input: crate::types::Software) -> Self {
        let mut v = self.software.unwrap_or_default();
        v.push(input);
        self.software = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the software components in the software set.</p>
    pub fn set_software(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Software>>) -> Self {
        self.software = input;
        self
    }
    /// <p>A list of the software components in the software set.</p>
    pub fn get_software(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Software>> {
        &self.software
    }
    /// <p>The Amazon Resource Name (ARN) of the software set.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the software set.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the software set.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// Consumes the builder and constructs a [`SoftwareSet`](crate::types::SoftwareSet).
    pub fn build(self) -> crate::types::SoftwareSet {
        crate::types::SoftwareSet {
            id: self.id,
            version: self.version,
            released_at: self.released_at,
            supported_until: self.supported_until,
            validation_status: self.validation_status,
            software: self.software,
            arn: self.arn,
        }
    }
}
