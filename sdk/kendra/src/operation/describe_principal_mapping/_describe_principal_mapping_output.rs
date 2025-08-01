// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribePrincipalMappingOutput {
    /// <p>Shows the identifier of the index to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub index_id: ::std::option::Option<::std::string::String>,
    /// <p>Shows the identifier of the data source to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub data_source_id: ::std::option::Option<::std::string::String>,
    /// <p>Shows the identifier of the group to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub group_id: ::std::option::Option<::std::string::String>,
    /// <p>Shows the following information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups:</p>
    /// <ul>
    /// <li>
    /// <p>Status—the status can be either <code>PROCESSING</code>, <code>SUCCEEDED</code>, <code>DELETING</code>, <code>DELETED</code>, or <code>FAILED</code>.</p></li>
    /// <li>
    /// <p>Last updated—the last date-time an action was updated.</p></li>
    /// <li>
    /// <p>Received—the last date-time an action was received or submitted.</p></li>
    /// <li>
    /// <p>Ordering ID—the latest action that should process and apply after other actions.</p></li>
    /// <li>
    /// <p>Failure reason—the reason an action could not be processed.</p></li>
    /// </ul>
    pub group_ordering_id_summaries: ::std::option::Option<::std::vec::Vec<crate::types::GroupOrderingIdSummary>>,
    _request_id: Option<String>,
}
impl DescribePrincipalMappingOutput {
    /// <p>Shows the identifier of the index to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn index_id(&self) -> ::std::option::Option<&str> {
        self.index_id.as_deref()
    }
    /// <p>Shows the identifier of the data source to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn data_source_id(&self) -> ::std::option::Option<&str> {
        self.data_source_id.as_deref()
    }
    /// <p>Shows the identifier of the group to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
    /// <p>Shows the following information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups:</p>
    /// <ul>
    /// <li>
    /// <p>Status—the status can be either <code>PROCESSING</code>, <code>SUCCEEDED</code>, <code>DELETING</code>, <code>DELETED</code>, or <code>FAILED</code>.</p></li>
    /// <li>
    /// <p>Last updated—the last date-time an action was updated.</p></li>
    /// <li>
    /// <p>Received—the last date-time an action was received or submitted.</p></li>
    /// <li>
    /// <p>Ordering ID—the latest action that should process and apply after other actions.</p></li>
    /// <li>
    /// <p>Failure reason—the reason an action could not be processed.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_ordering_id_summaries.is_none()`.
    pub fn group_ordering_id_summaries(&self) -> &[crate::types::GroupOrderingIdSummary] {
        self.group_ordering_id_summaries.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribePrincipalMappingOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribePrincipalMappingOutput {
    /// Creates a new builder-style object to manufacture [`DescribePrincipalMappingOutput`](crate::operation::describe_principal_mapping::DescribePrincipalMappingOutput).
    pub fn builder() -> crate::operation::describe_principal_mapping::builders::DescribePrincipalMappingOutputBuilder {
        crate::operation::describe_principal_mapping::builders::DescribePrincipalMappingOutputBuilder::default()
    }
}

/// A builder for [`DescribePrincipalMappingOutput`](crate::operation::describe_principal_mapping::DescribePrincipalMappingOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribePrincipalMappingOutputBuilder {
    pub(crate) index_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    pub(crate) group_ordering_id_summaries: ::std::option::Option<::std::vec::Vec<crate::types::GroupOrderingIdSummary>>,
    _request_id: Option<String>,
}
impl DescribePrincipalMappingOutputBuilder {
    /// <p>Shows the identifier of the index to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn index_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Shows the identifier of the index to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn set_index_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_id = input;
        self
    }
    /// <p>Shows the identifier of the index to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn get_index_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_id
    }
    /// <p>Shows the identifier of the data source to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn data_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Shows the identifier of the data source to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn set_data_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_id = input;
        self
    }
    /// <p>Shows the identifier of the data source to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn get_data_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_id
    }
    /// <p>Shows the identifier of the group to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Shows the identifier of the group to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// <p>Shows the identifier of the group to see information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups.</p>
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    /// Appends an item to `group_ordering_id_summaries`.
    ///
    /// To override the contents of this collection use [`set_group_ordering_id_summaries`](Self::set_group_ordering_id_summaries).
    ///
    /// <p>Shows the following information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups:</p>
    /// <ul>
    /// <li>
    /// <p>Status—the status can be either <code>PROCESSING</code>, <code>SUCCEEDED</code>, <code>DELETING</code>, <code>DELETED</code>, or <code>FAILED</code>.</p></li>
    /// <li>
    /// <p>Last updated—the last date-time an action was updated.</p></li>
    /// <li>
    /// <p>Received—the last date-time an action was received or submitted.</p></li>
    /// <li>
    /// <p>Ordering ID—the latest action that should process and apply after other actions.</p></li>
    /// <li>
    /// <p>Failure reason—the reason an action could not be processed.</p></li>
    /// </ul>
    pub fn group_ordering_id_summaries(mut self, input: crate::types::GroupOrderingIdSummary) -> Self {
        let mut v = self.group_ordering_id_summaries.unwrap_or_default();
        v.push(input);
        self.group_ordering_id_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>Shows the following information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups:</p>
    /// <ul>
    /// <li>
    /// <p>Status—the status can be either <code>PROCESSING</code>, <code>SUCCEEDED</code>, <code>DELETING</code>, <code>DELETED</code>, or <code>FAILED</code>.</p></li>
    /// <li>
    /// <p>Last updated—the last date-time an action was updated.</p></li>
    /// <li>
    /// <p>Received—the last date-time an action was received or submitted.</p></li>
    /// <li>
    /// <p>Ordering ID—the latest action that should process and apply after other actions.</p></li>
    /// <li>
    /// <p>Failure reason—the reason an action could not be processed.</p></li>
    /// </ul>
    pub fn set_group_ordering_id_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupOrderingIdSummary>>) -> Self {
        self.group_ordering_id_summaries = input;
        self
    }
    /// <p>Shows the following information on the processing of <code>PUT</code> and <code>DELETE</code> actions for mapping users to their groups:</p>
    /// <ul>
    /// <li>
    /// <p>Status—the status can be either <code>PROCESSING</code>, <code>SUCCEEDED</code>, <code>DELETING</code>, <code>DELETED</code>, or <code>FAILED</code>.</p></li>
    /// <li>
    /// <p>Last updated—the last date-time an action was updated.</p></li>
    /// <li>
    /// <p>Received—the last date-time an action was received or submitted.</p></li>
    /// <li>
    /// <p>Ordering ID—the latest action that should process and apply after other actions.</p></li>
    /// <li>
    /// <p>Failure reason—the reason an action could not be processed.</p></li>
    /// </ul>
    pub fn get_group_ordering_id_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupOrderingIdSummary>> {
        &self.group_ordering_id_summaries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribePrincipalMappingOutput`](crate::operation::describe_principal_mapping::DescribePrincipalMappingOutput).
    pub fn build(self) -> crate::operation::describe_principal_mapping::DescribePrincipalMappingOutput {
        crate::operation::describe_principal_mapping::DescribePrincipalMappingOutput {
            index_id: self.index_id,
            data_source_id: self.data_source_id,
            group_id: self.group_id,
            group_ordering_id_summaries: self.group_ordering_id_summaries,
            _request_id: self._request_id,
        }
    }
}
