// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary information for your Amazon Kendra experience. You can create an Amazon Kendra experience such as a search application. For more information on creating a search application experience, see <a href="https://docs.aws.amazon.com/kendra/latest/dg/deploying-search-experience-no-code.html">Building a search experience with no code</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExperiencesSummary {
    /// <p>The name of your Amazon Kendra experience.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of your Amazon Kendra experience.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Unix timestamp when your Amazon Kendra experience was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The processing status of your Amazon Kendra experience.</p>
    pub status: ::std::option::Option<crate::types::ExperienceStatus>,
    /// <p>The endpoint URLs for your Amazon Kendra experiences. The URLs are unique and fully hosted by Amazon Web Services.</p>
    pub endpoints: ::std::option::Option<::std::vec::Vec<crate::types::ExperienceEndpoint>>,
}
impl ExperiencesSummary {
    /// <p>The name of your Amazon Kendra experience.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The identifier of your Amazon Kendra experience.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Unix timestamp when your Amazon Kendra experience was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The processing status of your Amazon Kendra experience.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ExperienceStatus> {
        self.status.as_ref()
    }
    /// <p>The endpoint URLs for your Amazon Kendra experiences. The URLs are unique and fully hosted by Amazon Web Services.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.endpoints.is_none()`.
    pub fn endpoints(&self) -> &[crate::types::ExperienceEndpoint] {
        self.endpoints.as_deref().unwrap_or_default()
    }
}
impl ExperiencesSummary {
    /// Creates a new builder-style object to manufacture [`ExperiencesSummary`](crate::types::ExperiencesSummary).
    pub fn builder() -> crate::types::builders::ExperiencesSummaryBuilder {
        crate::types::builders::ExperiencesSummaryBuilder::default()
    }
}

/// A builder for [`ExperiencesSummary`](crate::types::ExperiencesSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExperiencesSummaryBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::ExperienceStatus>,
    pub(crate) endpoints: ::std::option::Option<::std::vec::Vec<crate::types::ExperienceEndpoint>>,
}
impl ExperiencesSummaryBuilder {
    /// <p>The name of your Amazon Kendra experience.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your Amazon Kendra experience.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of your Amazon Kendra experience.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The identifier of your Amazon Kendra experience.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of your Amazon Kendra experience.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of your Amazon Kendra experience.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Unix timestamp when your Amazon Kendra experience was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Unix timestamp when your Amazon Kendra experience was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp when your Amazon Kendra experience was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The processing status of your Amazon Kendra experience.</p>
    pub fn status(mut self, input: crate::types::ExperienceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The processing status of your Amazon Kendra experience.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ExperienceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The processing status of your Amazon Kendra experience.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ExperienceStatus> {
        &self.status
    }
    /// Appends an item to `endpoints`.
    ///
    /// To override the contents of this collection use [`set_endpoints`](Self::set_endpoints).
    ///
    /// <p>The endpoint URLs for your Amazon Kendra experiences. The URLs are unique and fully hosted by Amazon Web Services.</p>
    pub fn endpoints(mut self, input: crate::types::ExperienceEndpoint) -> Self {
        let mut v = self.endpoints.unwrap_or_default();
        v.push(input);
        self.endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>The endpoint URLs for your Amazon Kendra experiences. The URLs are unique and fully hosted by Amazon Web Services.</p>
    pub fn set_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExperienceEndpoint>>) -> Self {
        self.endpoints = input;
        self
    }
    /// <p>The endpoint URLs for your Amazon Kendra experiences. The URLs are unique and fully hosted by Amazon Web Services.</p>
    pub fn get_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExperienceEndpoint>> {
        &self.endpoints
    }
    /// Consumes the builder and constructs a [`ExperiencesSummary`](crate::types::ExperiencesSummary).
    pub fn build(self) -> crate::types::ExperiencesSummary {
        crate::types::ExperiencesSummary {
            name: self.name,
            id: self.id,
            created_at: self.created_at,
            status: self.status,
            endpoints: self.endpoints,
        }
    }
}
