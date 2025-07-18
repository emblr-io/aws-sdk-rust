// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Lake Formation configuration of the Data Lake blueprint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LakeFormationConfiguration {
    /// <p>The role that is used to manage read/write access to the chosen Amazon S3 bucket(s) for Data Lake using Amazon Web Services Lake Formation hybrid access mode.</p>
    pub location_registration_role: ::std::option::Option<::std::string::String>,
    /// <p>Specifies certain Amazon S3 locations if you do not want Amazon DataZone to automatically register them in hybrid mode.</p>
    pub location_registration_exclude_s3_locations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl LakeFormationConfiguration {
    /// <p>The role that is used to manage read/write access to the chosen Amazon S3 bucket(s) for Data Lake using Amazon Web Services Lake Formation hybrid access mode.</p>
    pub fn location_registration_role(&self) -> ::std::option::Option<&str> {
        self.location_registration_role.as_deref()
    }
    /// <p>Specifies certain Amazon S3 locations if you do not want Amazon DataZone to automatically register them in hybrid mode.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.location_registration_exclude_s3_locations.is_none()`.
    pub fn location_registration_exclude_s3_locations(&self) -> &[::std::string::String] {
        self.location_registration_exclude_s3_locations.as_deref().unwrap_or_default()
    }
}
impl LakeFormationConfiguration {
    /// Creates a new builder-style object to manufacture [`LakeFormationConfiguration`](crate::types::LakeFormationConfiguration).
    pub fn builder() -> crate::types::builders::LakeFormationConfigurationBuilder {
        crate::types::builders::LakeFormationConfigurationBuilder::default()
    }
}

/// A builder for [`LakeFormationConfiguration`](crate::types::LakeFormationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LakeFormationConfigurationBuilder {
    pub(crate) location_registration_role: ::std::option::Option<::std::string::String>,
    pub(crate) location_registration_exclude_s3_locations: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl LakeFormationConfigurationBuilder {
    /// <p>The role that is used to manage read/write access to the chosen Amazon S3 bucket(s) for Data Lake using Amazon Web Services Lake Formation hybrid access mode.</p>
    pub fn location_registration_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_registration_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The role that is used to manage read/write access to the chosen Amazon S3 bucket(s) for Data Lake using Amazon Web Services Lake Formation hybrid access mode.</p>
    pub fn set_location_registration_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_registration_role = input;
        self
    }
    /// <p>The role that is used to manage read/write access to the chosen Amazon S3 bucket(s) for Data Lake using Amazon Web Services Lake Formation hybrid access mode.</p>
    pub fn get_location_registration_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_registration_role
    }
    /// Appends an item to `location_registration_exclude_s3_locations`.
    ///
    /// To override the contents of this collection use [`set_location_registration_exclude_s3_locations`](Self::set_location_registration_exclude_s3_locations).
    ///
    /// <p>Specifies certain Amazon S3 locations if you do not want Amazon DataZone to automatically register them in hybrid mode.</p>
    pub fn location_registration_exclude_s3_locations(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.location_registration_exclude_s3_locations.unwrap_or_default();
        v.push(input.into());
        self.location_registration_exclude_s3_locations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies certain Amazon S3 locations if you do not want Amazon DataZone to automatically register them in hybrid mode.</p>
    pub fn set_location_registration_exclude_s3_locations(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.location_registration_exclude_s3_locations = input;
        self
    }
    /// <p>Specifies certain Amazon S3 locations if you do not want Amazon DataZone to automatically register them in hybrid mode.</p>
    pub fn get_location_registration_exclude_s3_locations(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.location_registration_exclude_s3_locations
    }
    /// Consumes the builder and constructs a [`LakeFormationConfiguration`](crate::types::LakeFormationConfiguration).
    pub fn build(self) -> crate::types::LakeFormationConfiguration {
        crate::types::LakeFormationConfiguration {
            location_registration_role: self.location_registration_role,
            location_registration_exclude_s3_locations: self.location_registration_exclude_s3_locations,
        }
    }
}
