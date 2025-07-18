// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An ordered list of preferred challenge type and versions.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChallengePreference {
    /// <p>The types of challenges that have been selected for the Face Liveness session.</p>
    pub r#type: crate::types::ChallengeType,
    /// <p>The version of the challenges that have been selected for the Face Liveness session.</p>
    pub versions: ::std::option::Option<crate::types::Versions>,
}
impl ChallengePreference {
    /// <p>The types of challenges that have been selected for the Face Liveness session.</p>
    pub fn r#type(&self) -> &crate::types::ChallengeType {
        &self.r#type
    }
    /// <p>The version of the challenges that have been selected for the Face Liveness session.</p>
    pub fn versions(&self) -> ::std::option::Option<&crate::types::Versions> {
        self.versions.as_ref()
    }
}
impl ChallengePreference {
    /// Creates a new builder-style object to manufacture [`ChallengePreference`](crate::types::ChallengePreference).
    pub fn builder() -> crate::types::builders::ChallengePreferenceBuilder {
        crate::types::builders::ChallengePreferenceBuilder::default()
    }
}

/// A builder for [`ChallengePreference`](crate::types::ChallengePreference).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChallengePreferenceBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ChallengeType>,
    pub(crate) versions: ::std::option::Option<crate::types::Versions>,
}
impl ChallengePreferenceBuilder {
    /// <p>The types of challenges that have been selected for the Face Liveness session.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ChallengeType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The types of challenges that have been selected for the Face Liveness session.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ChallengeType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The types of challenges that have been selected for the Face Liveness session.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ChallengeType> {
        &self.r#type
    }
    /// <p>The version of the challenges that have been selected for the Face Liveness session.</p>
    pub fn versions(mut self, input: crate::types::Versions) -> Self {
        self.versions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the challenges that have been selected for the Face Liveness session.</p>
    pub fn set_versions(mut self, input: ::std::option::Option<crate::types::Versions>) -> Self {
        self.versions = input;
        self
    }
    /// <p>The version of the challenges that have been selected for the Face Liveness session.</p>
    pub fn get_versions(&self) -> &::std::option::Option<crate::types::Versions> {
        &self.versions
    }
    /// Consumes the builder and constructs a [`ChallengePreference`](crate::types::ChallengePreference).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::ChallengePreferenceBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::ChallengePreference, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChallengePreference {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building ChallengePreference",
                )
            })?,
            versions: self.versions,
        })
    }
}
