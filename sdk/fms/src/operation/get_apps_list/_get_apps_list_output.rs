// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAppsListOutput {
    /// <p>Information about the specified Firewall Manager applications list.</p>
    pub apps_list: ::std::option::Option<crate::types::AppsListData>,
    /// <p>The Amazon Resource Name (ARN) of the applications list.</p>
    pub apps_list_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAppsListOutput {
    /// <p>Information about the specified Firewall Manager applications list.</p>
    pub fn apps_list(&self) -> ::std::option::Option<&crate::types::AppsListData> {
        self.apps_list.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the applications list.</p>
    pub fn apps_list_arn(&self) -> ::std::option::Option<&str> {
        self.apps_list_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetAppsListOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAppsListOutput {
    /// Creates a new builder-style object to manufacture [`GetAppsListOutput`](crate::operation::get_apps_list::GetAppsListOutput).
    pub fn builder() -> crate::operation::get_apps_list::builders::GetAppsListOutputBuilder {
        crate::operation::get_apps_list::builders::GetAppsListOutputBuilder::default()
    }
}

/// A builder for [`GetAppsListOutput`](crate::operation::get_apps_list::GetAppsListOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAppsListOutputBuilder {
    pub(crate) apps_list: ::std::option::Option<crate::types::AppsListData>,
    pub(crate) apps_list_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAppsListOutputBuilder {
    /// <p>Information about the specified Firewall Manager applications list.</p>
    pub fn apps_list(mut self, input: crate::types::AppsListData) -> Self {
        self.apps_list = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the specified Firewall Manager applications list.</p>
    pub fn set_apps_list(mut self, input: ::std::option::Option<crate::types::AppsListData>) -> Self {
        self.apps_list = input;
        self
    }
    /// <p>Information about the specified Firewall Manager applications list.</p>
    pub fn get_apps_list(&self) -> &::std::option::Option<crate::types::AppsListData> {
        &self.apps_list
    }
    /// <p>The Amazon Resource Name (ARN) of the applications list.</p>
    pub fn apps_list_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.apps_list_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the applications list.</p>
    pub fn set_apps_list_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.apps_list_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the applications list.</p>
    pub fn get_apps_list_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.apps_list_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAppsListOutput`](crate::operation::get_apps_list::GetAppsListOutput).
    pub fn build(self) -> crate::operation::get_apps_list::GetAppsListOutput {
        crate::operation::get_apps_list::GetAppsListOutput {
            apps_list: self.apps_list,
            apps_list_arn: self.apps_list_arn,
            _request_id: self._request_id,
        }
    }
}
