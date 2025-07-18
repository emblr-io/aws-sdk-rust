// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Description of ephemeris.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EphemerisDescription {
    /// <p>Source S3 object used for the ephemeris.</p>
    pub source_s3_object: ::std::option::Option<crate::types::S3Object>,
    /// <p>Supplied ephemeris data.</p>
    pub ephemeris_data: ::std::option::Option<::std::string::String>,
}
impl EphemerisDescription {
    /// <p>Source S3 object used for the ephemeris.</p>
    pub fn source_s3_object(&self) -> ::std::option::Option<&crate::types::S3Object> {
        self.source_s3_object.as_ref()
    }
    /// <p>Supplied ephemeris data.</p>
    pub fn ephemeris_data(&self) -> ::std::option::Option<&str> {
        self.ephemeris_data.as_deref()
    }
}
impl EphemerisDescription {
    /// Creates a new builder-style object to manufacture [`EphemerisDescription`](crate::types::EphemerisDescription).
    pub fn builder() -> crate::types::builders::EphemerisDescriptionBuilder {
        crate::types::builders::EphemerisDescriptionBuilder::default()
    }
}

/// A builder for [`EphemerisDescription`](crate::types::EphemerisDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EphemerisDescriptionBuilder {
    pub(crate) source_s3_object: ::std::option::Option<crate::types::S3Object>,
    pub(crate) ephemeris_data: ::std::option::Option<::std::string::String>,
}
impl EphemerisDescriptionBuilder {
    /// <p>Source S3 object used for the ephemeris.</p>
    pub fn source_s3_object(mut self, input: crate::types::S3Object) -> Self {
        self.source_s3_object = ::std::option::Option::Some(input);
        self
    }
    /// <p>Source S3 object used for the ephemeris.</p>
    pub fn set_source_s3_object(mut self, input: ::std::option::Option<crate::types::S3Object>) -> Self {
        self.source_s3_object = input;
        self
    }
    /// <p>Source S3 object used for the ephemeris.</p>
    pub fn get_source_s3_object(&self) -> &::std::option::Option<crate::types::S3Object> {
        &self.source_s3_object
    }
    /// <p>Supplied ephemeris data.</p>
    pub fn ephemeris_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ephemeris_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Supplied ephemeris data.</p>
    pub fn set_ephemeris_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ephemeris_data = input;
        self
    }
    /// <p>Supplied ephemeris data.</p>
    pub fn get_ephemeris_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.ephemeris_data
    }
    /// Consumes the builder and constructs a [`EphemerisDescription`](crate::types::EphemerisDescription).
    pub fn build(self) -> crate::types::EphemerisDescription {
        crate::types::EphemerisDescription {
            source_s3_object: self.source_s3_object,
            ephemeris_data: self.ephemeris_data,
        }
    }
}
