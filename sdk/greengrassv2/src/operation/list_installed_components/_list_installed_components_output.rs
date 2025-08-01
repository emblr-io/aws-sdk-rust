// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListInstalledComponentsOutput {
    /// <p>A list that summarizes each component on the core device.</p><note>
    /// <p>Greengrass nucleus v2.7.0 or later is required to get an accurate <code>lastStatusChangeTimestamp</code> response. This response can be inaccurate in earlier Greengrass nucleus versions.</p>
    /// </note> <note>
    /// <p>Greengrass nucleus v2.8.0 or later is required to get an accurate <code>lastInstallationSource</code> and <code>lastReportedTimestamp</code> response. This response can be inaccurate or null in earlier Greengrass nucleus versions.</p>
    /// </note>
    pub installed_components: ::std::option::Option<::std::vec::Vec<crate::types::InstalledComponent>>,
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInstalledComponentsOutput {
    /// <p>A list that summarizes each component on the core device.</p><note>
    /// <p>Greengrass nucleus v2.7.0 or later is required to get an accurate <code>lastStatusChangeTimestamp</code> response. This response can be inaccurate in earlier Greengrass nucleus versions.</p>
    /// </note> <note>
    /// <p>Greengrass nucleus v2.8.0 or later is required to get an accurate <code>lastInstallationSource</code> and <code>lastReportedTimestamp</code> response. This response can be inaccurate or null in earlier Greengrass nucleus versions.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.installed_components.is_none()`.
    pub fn installed_components(&self) -> &[crate::types::InstalledComponent] {
        self.installed_components.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListInstalledComponentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListInstalledComponentsOutput {
    /// Creates a new builder-style object to manufacture [`ListInstalledComponentsOutput`](crate::operation::list_installed_components::ListInstalledComponentsOutput).
    pub fn builder() -> crate::operation::list_installed_components::builders::ListInstalledComponentsOutputBuilder {
        crate::operation::list_installed_components::builders::ListInstalledComponentsOutputBuilder::default()
    }
}

/// A builder for [`ListInstalledComponentsOutput`](crate::operation::list_installed_components::ListInstalledComponentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListInstalledComponentsOutputBuilder {
    pub(crate) installed_components: ::std::option::Option<::std::vec::Vec<crate::types::InstalledComponent>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListInstalledComponentsOutputBuilder {
    /// Appends an item to `installed_components`.
    ///
    /// To override the contents of this collection use [`set_installed_components`](Self::set_installed_components).
    ///
    /// <p>A list that summarizes each component on the core device.</p><note>
    /// <p>Greengrass nucleus v2.7.0 or later is required to get an accurate <code>lastStatusChangeTimestamp</code> response. This response can be inaccurate in earlier Greengrass nucleus versions.</p>
    /// </note> <note>
    /// <p>Greengrass nucleus v2.8.0 or later is required to get an accurate <code>lastInstallationSource</code> and <code>lastReportedTimestamp</code> response. This response can be inaccurate or null in earlier Greengrass nucleus versions.</p>
    /// </note>
    pub fn installed_components(mut self, input: crate::types::InstalledComponent) -> Self {
        let mut v = self.installed_components.unwrap_or_default();
        v.push(input);
        self.installed_components = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list that summarizes each component on the core device.</p><note>
    /// <p>Greengrass nucleus v2.7.0 or later is required to get an accurate <code>lastStatusChangeTimestamp</code> response. This response can be inaccurate in earlier Greengrass nucleus versions.</p>
    /// </note> <note>
    /// <p>Greengrass nucleus v2.8.0 or later is required to get an accurate <code>lastInstallationSource</code> and <code>lastReportedTimestamp</code> response. This response can be inaccurate or null in earlier Greengrass nucleus versions.</p>
    /// </note>
    pub fn set_installed_components(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::InstalledComponent>>) -> Self {
        self.installed_components = input;
        self
    }
    /// <p>A list that summarizes each component on the core device.</p><note>
    /// <p>Greengrass nucleus v2.7.0 or later is required to get an accurate <code>lastStatusChangeTimestamp</code> response. This response can be inaccurate in earlier Greengrass nucleus versions.</p>
    /// </note> <note>
    /// <p>Greengrass nucleus v2.8.0 or later is required to get an accurate <code>lastInstallationSource</code> and <code>lastReportedTimestamp</code> response. This response can be inaccurate or null in earlier Greengrass nucleus versions.</p>
    /// </note>
    pub fn get_installed_components(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InstalledComponent>> {
        &self.installed_components
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no additional results.</p>
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
    /// Consumes the builder and constructs a [`ListInstalledComponentsOutput`](crate::operation::list_installed_components::ListInstalledComponentsOutput).
    pub fn build(self) -> crate::operation::list_installed_components::ListInstalledComponentsOutput {
        crate::operation::list_installed_components::ListInstalledComponentsOutput {
            installed_components: self.installed_components,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
