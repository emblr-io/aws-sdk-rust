// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyDbClusterParameterGroupOutput {
    /// <p>The name of the DB cluster parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 255 letters or numbers.</p></li>
    /// <li>
    /// <p>First character must be a letter</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul><note>
    /// <p>This value is stored as a lowercase string.</p>
    /// </note>
    pub db_cluster_parameter_group_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ModifyDbClusterParameterGroupOutput {
    /// <p>The name of the DB cluster parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 255 letters or numbers.</p></li>
    /// <li>
    /// <p>First character must be a letter</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul><note>
    /// <p>This value is stored as a lowercase string.</p>
    /// </note>
    pub fn db_cluster_parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.db_cluster_parameter_group_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyDbClusterParameterGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyDbClusterParameterGroupOutput {
    /// Creates a new builder-style object to manufacture [`ModifyDbClusterParameterGroupOutput`](crate::operation::modify_db_cluster_parameter_group::ModifyDbClusterParameterGroupOutput).
    pub fn builder() -> crate::operation::modify_db_cluster_parameter_group::builders::ModifyDbClusterParameterGroupOutputBuilder {
        crate::operation::modify_db_cluster_parameter_group::builders::ModifyDbClusterParameterGroupOutputBuilder::default()
    }
}

/// A builder for [`ModifyDbClusterParameterGroupOutput`](crate::operation::modify_db_cluster_parameter_group::ModifyDbClusterParameterGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyDbClusterParameterGroupOutputBuilder {
    pub(crate) db_cluster_parameter_group_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ModifyDbClusterParameterGroupOutputBuilder {
    /// <p>The name of the DB cluster parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 255 letters or numbers.</p></li>
    /// <li>
    /// <p>First character must be a letter</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul><note>
    /// <p>This value is stored as a lowercase string.</p>
    /// </note>
    pub fn db_cluster_parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_cluster_parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB cluster parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 255 letters or numbers.</p></li>
    /// <li>
    /// <p>First character must be a letter</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul><note>
    /// <p>This value is stored as a lowercase string.</p>
    /// </note>
    pub fn set_db_cluster_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_cluster_parameter_group_name = input;
        self
    }
    /// <p>The name of the DB cluster parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 255 letters or numbers.</p></li>
    /// <li>
    /// <p>First character must be a letter</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens</p></li>
    /// </ul><note>
    /// <p>This value is stored as a lowercase string.</p>
    /// </note>
    pub fn get_db_cluster_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_cluster_parameter_group_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyDbClusterParameterGroupOutput`](crate::operation::modify_db_cluster_parameter_group::ModifyDbClusterParameterGroupOutput).
    pub fn build(self) -> crate::operation::modify_db_cluster_parameter_group::ModifyDbClusterParameterGroupOutput {
        crate::operation::modify_db_cluster_parameter_group::ModifyDbClusterParameterGroupOutput {
            db_cluster_parameter_group_name: self.db_cluster_parameter_group_name,
            _request_id: self._request_id,
        }
    }
}
