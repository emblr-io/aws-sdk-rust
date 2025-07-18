// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPackageGroupsOutput {
    /// <p>The list of package groups in the requested domain.</p>
    pub package_groups: ::std::option::Option<::std::vec::Vec<crate::types::PackageGroupSummary>>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPackageGroupsOutput {
    /// <p>The list of package groups in the requested domain.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.package_groups.is_none()`.
    pub fn package_groups(&self) -> &[crate::types::PackageGroupSummary] {
        self.package_groups.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPackageGroupsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPackageGroupsOutput {
    /// Creates a new builder-style object to manufacture [`ListPackageGroupsOutput`](crate::operation::list_package_groups::ListPackageGroupsOutput).
    pub fn builder() -> crate::operation::list_package_groups::builders::ListPackageGroupsOutputBuilder {
        crate::operation::list_package_groups::builders::ListPackageGroupsOutputBuilder::default()
    }
}

/// A builder for [`ListPackageGroupsOutput`](crate::operation::list_package_groups::ListPackageGroupsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPackageGroupsOutputBuilder {
    pub(crate) package_groups: ::std::option::Option<::std::vec::Vec<crate::types::PackageGroupSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPackageGroupsOutputBuilder {
    /// Appends an item to `package_groups`.
    ///
    /// To override the contents of this collection use [`set_package_groups`](Self::set_package_groups).
    ///
    /// <p>The list of package groups in the requested domain.</p>
    pub fn package_groups(mut self, input: crate::types::PackageGroupSummary) -> Self {
        let mut v = self.package_groups.unwrap_or_default();
        v.push(input);
        self.package_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of package groups in the requested domain.</p>
    pub fn set_package_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PackageGroupSummary>>) -> Self {
        self.package_groups = input;
        self
    }
    /// <p>The list of package groups in the requested domain.</p>
    pub fn get_package_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PackageGroupSummary>> {
        &self.package_groups
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPackageGroupsOutput`](crate::operation::list_package_groups::ListPackageGroupsOutput).
    pub fn build(self) -> crate::operation::list_package_groups::ListPackageGroupsOutput {
        crate::operation::list_package_groups::ListPackageGroupsOutput {
            package_groups: self.package_groups,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
