// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListServiceProfilesOutput {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The list of service profiles.</p>
    pub service_profile_list: ::std::option::Option<::std::vec::Vec<crate::types::ServiceProfile>>,
    _request_id: Option<String>,
}
impl ListServiceProfilesOutput {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The list of service profiles.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_profile_list.is_none()`.
    pub fn service_profile_list(&self) -> &[crate::types::ServiceProfile] {
        self.service_profile_list.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListServiceProfilesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListServiceProfilesOutput {
    /// Creates a new builder-style object to manufacture [`ListServiceProfilesOutput`](crate::operation::list_service_profiles::ListServiceProfilesOutput).
    pub fn builder() -> crate::operation::list_service_profiles::builders::ListServiceProfilesOutputBuilder {
        crate::operation::list_service_profiles::builders::ListServiceProfilesOutputBuilder::default()
    }
}

/// A builder for [`ListServiceProfilesOutput`](crate::operation::list_service_profiles::ListServiceProfilesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListServiceProfilesOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) service_profile_list: ::std::option::Option<::std::vec::Vec<crate::types::ServiceProfile>>,
    _request_id: Option<String>,
}
impl ListServiceProfilesOutputBuilder {
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to get the next set of results, or <b>null</b> if there are no additional results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `service_profile_list`.
    ///
    /// To override the contents of this collection use [`set_service_profile_list`](Self::set_service_profile_list).
    ///
    /// <p>The list of service profiles.</p>
    pub fn service_profile_list(mut self, input: crate::types::ServiceProfile) -> Self {
        let mut v = self.service_profile_list.unwrap_or_default();
        v.push(input);
        self.service_profile_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of service profiles.</p>
    pub fn set_service_profile_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceProfile>>) -> Self {
        self.service_profile_list = input;
        self
    }
    /// <p>The list of service profiles.</p>
    pub fn get_service_profile_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceProfile>> {
        &self.service_profile_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListServiceProfilesOutput`](crate::operation::list_service_profiles::ListServiceProfilesOutput).
    pub fn build(self) -> crate::operation::list_service_profiles::ListServiceProfilesOutput {
        crate::operation::list_service_profiles::ListServiceProfilesOutput {
            next_token: self.next_token,
            service_profile_list: self.service_profile_list,
            _request_id: self._request_id,
        }
    }
}
