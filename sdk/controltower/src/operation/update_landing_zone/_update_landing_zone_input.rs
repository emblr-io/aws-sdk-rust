// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLandingZoneInput {
    /// <p>The landing zone version, for example, 3.2.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The manifest file (JSON) is a text file that describes your Amazon Web Services resources. For an example, review <a href="https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch">Launch your landing zone</a>. The example manifest file contains each of the available parameters. The schema for the landing zone's JSON manifest file is not published, by design.</p>
    pub manifest: ::std::option::Option<::aws_smithy_types::Document>,
    /// <p>The unique identifier of the landing zone.</p>
    pub landing_zone_identifier: ::std::option::Option<::std::string::String>,
}
impl UpdateLandingZoneInput {
    /// <p>The landing zone version, for example, 3.2.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The manifest file (JSON) is a text file that describes your Amazon Web Services resources. For an example, review <a href="https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch">Launch your landing zone</a>. The example manifest file contains each of the available parameters. The schema for the landing zone's JSON manifest file is not published, by design.</p>
    pub fn manifest(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.manifest.as_ref()
    }
    /// <p>The unique identifier of the landing zone.</p>
    pub fn landing_zone_identifier(&self) -> ::std::option::Option<&str> {
        self.landing_zone_identifier.as_deref()
    }
}
impl UpdateLandingZoneInput {
    /// Creates a new builder-style object to manufacture [`UpdateLandingZoneInput`](crate::operation::update_landing_zone::UpdateLandingZoneInput).
    pub fn builder() -> crate::operation::update_landing_zone::builders::UpdateLandingZoneInputBuilder {
        crate::operation::update_landing_zone::builders::UpdateLandingZoneInputBuilder::default()
    }
}

/// A builder for [`UpdateLandingZoneInput`](crate::operation::update_landing_zone::UpdateLandingZoneInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLandingZoneInputBuilder {
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) manifest: ::std::option::Option<::aws_smithy_types::Document>,
    pub(crate) landing_zone_identifier: ::std::option::Option<::std::string::String>,
}
impl UpdateLandingZoneInputBuilder {
    /// <p>The landing zone version, for example, 3.2.</p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The landing zone version, for example, 3.2.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The landing zone version, for example, 3.2.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The manifest file (JSON) is a text file that describes your Amazon Web Services resources. For an example, review <a href="https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch">Launch your landing zone</a>. The example manifest file contains each of the available parameters. The schema for the landing zone's JSON manifest file is not published, by design.</p>
    /// This field is required.
    pub fn manifest(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.manifest = ::std::option::Option::Some(input);
        self
    }
    /// <p>The manifest file (JSON) is a text file that describes your Amazon Web Services resources. For an example, review <a href="https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch">Launch your landing zone</a>. The example manifest file contains each of the available parameters. The schema for the landing zone's JSON manifest file is not published, by design.</p>
    pub fn set_manifest(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.manifest = input;
        self
    }
    /// <p>The manifest file (JSON) is a text file that describes your Amazon Web Services resources. For an example, review <a href="https://docs.aws.amazon.com/controltower/latest/userguide/lz-api-launch">Launch your landing zone</a>. The example manifest file contains each of the available parameters. The schema for the landing zone's JSON manifest file is not published, by design.</p>
    pub fn get_manifest(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.manifest
    }
    /// <p>The unique identifier of the landing zone.</p>
    /// This field is required.
    pub fn landing_zone_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.landing_zone_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the landing zone.</p>
    pub fn set_landing_zone_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.landing_zone_identifier = input;
        self
    }
    /// <p>The unique identifier of the landing zone.</p>
    pub fn get_landing_zone_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.landing_zone_identifier
    }
    /// Consumes the builder and constructs a [`UpdateLandingZoneInput`](crate::operation::update_landing_zone::UpdateLandingZoneInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_landing_zone::UpdateLandingZoneInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_landing_zone::UpdateLandingZoneInput {
            version: self.version,
            manifest: self.manifest,
            landing_zone_identifier: self.landing_zone_identifier,
        })
    }
}
