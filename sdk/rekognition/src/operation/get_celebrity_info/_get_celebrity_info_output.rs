// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCelebrityInfoOutput {
    /// <p>An array of URLs pointing to additional celebrity information.</p>
    pub urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the celebrity.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Retrieves the known gender for the celebrity.</p>
    pub known_gender: ::std::option::Option<crate::types::KnownGender>,
    _request_id: Option<String>,
}
impl GetCelebrityInfoOutput {
    /// <p>An array of URLs pointing to additional celebrity information.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.urls.is_none()`.
    pub fn urls(&self) -> &[::std::string::String] {
        self.urls.as_deref().unwrap_or_default()
    }
    /// <p>The name of the celebrity.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Retrieves the known gender for the celebrity.</p>
    pub fn known_gender(&self) -> ::std::option::Option<&crate::types::KnownGender> {
        self.known_gender.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetCelebrityInfoOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCelebrityInfoOutput {
    /// Creates a new builder-style object to manufacture [`GetCelebrityInfoOutput`](crate::operation::get_celebrity_info::GetCelebrityInfoOutput).
    pub fn builder() -> crate::operation::get_celebrity_info::builders::GetCelebrityInfoOutputBuilder {
        crate::operation::get_celebrity_info::builders::GetCelebrityInfoOutputBuilder::default()
    }
}

/// A builder for [`GetCelebrityInfoOutput`](crate::operation::get_celebrity_info::GetCelebrityInfoOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCelebrityInfoOutputBuilder {
    pub(crate) urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) known_gender: ::std::option::Option<crate::types::KnownGender>,
    _request_id: Option<String>,
}
impl GetCelebrityInfoOutputBuilder {
    /// Appends an item to `urls`.
    ///
    /// To override the contents of this collection use [`set_urls`](Self::set_urls).
    ///
    /// <p>An array of URLs pointing to additional celebrity information.</p>
    pub fn urls(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.urls.unwrap_or_default();
        v.push(input.into());
        self.urls = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of URLs pointing to additional celebrity information.</p>
    pub fn set_urls(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.urls = input;
        self
    }
    /// <p>An array of URLs pointing to additional celebrity information.</p>
    pub fn get_urls(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.urls
    }
    /// <p>The name of the celebrity.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the celebrity.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the celebrity.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Retrieves the known gender for the celebrity.</p>
    pub fn known_gender(mut self, input: crate::types::KnownGender) -> Self {
        self.known_gender = ::std::option::Option::Some(input);
        self
    }
    /// <p>Retrieves the known gender for the celebrity.</p>
    pub fn set_known_gender(mut self, input: ::std::option::Option<crate::types::KnownGender>) -> Self {
        self.known_gender = input;
        self
    }
    /// <p>Retrieves the known gender for the celebrity.</p>
    pub fn get_known_gender(&self) -> &::std::option::Option<crate::types::KnownGender> {
        &self.known_gender
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCelebrityInfoOutput`](crate::operation::get_celebrity_info::GetCelebrityInfoOutput).
    pub fn build(self) -> crate::operation::get_celebrity_info::GetCelebrityInfoOutput {
        crate::operation::get_celebrity_info::GetCelebrityInfoOutput {
            urls: self.urls,
            name: self.name,
            known_gender: self.known_gender,
            _request_id: self._request_id,
        }
    }
}
