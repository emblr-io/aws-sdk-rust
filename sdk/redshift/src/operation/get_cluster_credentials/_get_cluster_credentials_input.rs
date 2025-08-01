// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request parameters to get cluster credentials.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetClusterCredentialsInput {
    /// <p>The name of a database user. If a user name matching <code>DbUser</code> exists in the database, the temporary user credentials have the same permissions as the existing user. If <code>DbUser</code> doesn't exist in the database and <code>Autocreate</code> is <code>True</code>, a new user is created using the value for <code>DbUser</code> with PUBLIC permissions. If a database user matching the value for <code>DbUser</code> doesn't exist and <code>Autocreate</code> is <code>False</code>, then the command succeeds but the connection attempt will fail because the user doesn't exist in the database.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_CREATE_USER.html">CREATE USER</a> in the Amazon Redshift Database Developer Guide.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens. The user name can't be <code>PUBLIC</code>.</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub db_user: ::std::option::Option<::std::string::String>,
    /// <p>The name of a database that <code>DbUser</code> is authorized to log on to. If <code>DbName</code> is not specified, <code>DbUser</code> can log on to any existing database.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub db_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the cluster that contains the database for which you are requesting credentials. This parameter is case sensitive.</p>
    pub cluster_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The number of seconds until the returned temporary password expires.</p>
    /// <p>Constraint: minimum 900, maximum 3600.</p>
    /// <p>Default: 900</p>
    pub duration_seconds: ::std::option::Option<i32>,
    /// <p>Create a database user with the name specified for the user named in <code>DbUser</code> if one does not exist.</p>
    pub auto_create: ::std::option::Option<bool>,
    /// <p>A list of the names of existing database groups that the user named in <code>DbUser</code> will join for the current session, in addition to any group memberships for an existing user. If not specified, a new user is added only to PUBLIC.</p>
    /// <p>Database group name constraints</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain only lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub db_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The custom domain name for the cluster credentials.</p>
    pub custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl GetClusterCredentialsInput {
    /// <p>The name of a database user. If a user name matching <code>DbUser</code> exists in the database, the temporary user credentials have the same permissions as the existing user. If <code>DbUser</code> doesn't exist in the database and <code>Autocreate</code> is <code>True</code>, a new user is created using the value for <code>DbUser</code> with PUBLIC permissions. If a database user matching the value for <code>DbUser</code> doesn't exist and <code>Autocreate</code> is <code>False</code>, then the command succeeds but the connection attempt will fail because the user doesn't exist in the database.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_CREATE_USER.html">CREATE USER</a> in the Amazon Redshift Database Developer Guide.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens. The user name can't be <code>PUBLIC</code>.</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn db_user(&self) -> ::std::option::Option<&str> {
        self.db_user.as_deref()
    }
    /// <p>The name of a database that <code>DbUser</code> is authorized to log on to. If <code>DbName</code> is not specified, <code>DbUser</code> can log on to any existing database.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn db_name(&self) -> ::std::option::Option<&str> {
        self.db_name.as_deref()
    }
    /// <p>The unique identifier of the cluster that contains the database for which you are requesting credentials. This parameter is case sensitive.</p>
    pub fn cluster_identifier(&self) -> ::std::option::Option<&str> {
        self.cluster_identifier.as_deref()
    }
    /// <p>The number of seconds until the returned temporary password expires.</p>
    /// <p>Constraint: minimum 900, maximum 3600.</p>
    /// <p>Default: 900</p>
    pub fn duration_seconds(&self) -> ::std::option::Option<i32> {
        self.duration_seconds
    }
    /// <p>Create a database user with the name specified for the user named in <code>DbUser</code> if one does not exist.</p>
    pub fn auto_create(&self) -> ::std::option::Option<bool> {
        self.auto_create
    }
    /// <p>A list of the names of existing database groups that the user named in <code>DbUser</code> will join for the current session, in addition to any group memberships for an existing user. If not specified, a new user is added only to PUBLIC.</p>
    /// <p>Database group name constraints</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain only lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.db_groups.is_none()`.
    pub fn db_groups(&self) -> &[::std::string::String] {
        self.db_groups.as_deref().unwrap_or_default()
    }
    /// <p>The custom domain name for the cluster credentials.</p>
    pub fn custom_domain_name(&self) -> ::std::option::Option<&str> {
        self.custom_domain_name.as_deref()
    }
}
impl GetClusterCredentialsInput {
    /// Creates a new builder-style object to manufacture [`GetClusterCredentialsInput`](crate::operation::get_cluster_credentials::GetClusterCredentialsInput).
    pub fn builder() -> crate::operation::get_cluster_credentials::builders::GetClusterCredentialsInputBuilder {
        crate::operation::get_cluster_credentials::builders::GetClusterCredentialsInputBuilder::default()
    }
}

/// A builder for [`GetClusterCredentialsInput`](crate::operation::get_cluster_credentials::GetClusterCredentialsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetClusterCredentialsInputBuilder {
    pub(crate) db_user: ::std::option::Option<::std::string::String>,
    pub(crate) db_name: ::std::option::Option<::std::string::String>,
    pub(crate) cluster_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) duration_seconds: ::std::option::Option<i32>,
    pub(crate) auto_create: ::std::option::Option<bool>,
    pub(crate) db_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) custom_domain_name: ::std::option::Option<::std::string::String>,
}
impl GetClusterCredentialsInputBuilder {
    /// <p>The name of a database user. If a user name matching <code>DbUser</code> exists in the database, the temporary user credentials have the same permissions as the existing user. If <code>DbUser</code> doesn't exist in the database and <code>Autocreate</code> is <code>True</code>, a new user is created using the value for <code>DbUser</code> with PUBLIC permissions. If a database user matching the value for <code>DbUser</code> doesn't exist and <code>Autocreate</code> is <code>False</code>, then the command succeeds but the connection attempt will fail because the user doesn't exist in the database.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_CREATE_USER.html">CREATE USER</a> in the Amazon Redshift Database Developer Guide.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens. The user name can't be <code>PUBLIC</code>.</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    /// This field is required.
    pub fn db_user(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_user = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a database user. If a user name matching <code>DbUser</code> exists in the database, the temporary user credentials have the same permissions as the existing user. If <code>DbUser</code> doesn't exist in the database and <code>Autocreate</code> is <code>True</code>, a new user is created using the value for <code>DbUser</code> with PUBLIC permissions. If a database user matching the value for <code>DbUser</code> doesn't exist and <code>Autocreate</code> is <code>False</code>, then the command succeeds but the connection attempt will fail because the user doesn't exist in the database.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_CREATE_USER.html">CREATE USER</a> in the Amazon Redshift Database Developer Guide.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens. The user name can't be <code>PUBLIC</code>.</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn set_db_user(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_user = input;
        self
    }
    /// <p>The name of a database user. If a user name matching <code>DbUser</code> exists in the database, the temporary user credentials have the same permissions as the existing user. If <code>DbUser</code> doesn't exist in the database and <code>Autocreate</code> is <code>True</code>, a new user is created using the value for <code>DbUser</code> with PUBLIC permissions. If a database user matching the value for <code>DbUser</code> doesn't exist and <code>Autocreate</code> is <code>False</code>, then the command succeeds but the connection attempt will fail because the user doesn't exist in the database.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_CREATE_USER.html">CREATE USER</a> in the Amazon Redshift Database Developer Guide.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens. The user name can't be <code>PUBLIC</code>.</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn get_db_user(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_user
    }
    /// <p>The name of a database that <code>DbUser</code> is authorized to log on to. If <code>DbName</code> is not specified, <code>DbUser</code> can log on to any existing database.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn db_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a database that <code>DbUser</code> is authorized to log on to. If <code>DbName</code> is not specified, <code>DbUser</code> can log on to any existing database.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn set_db_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_name = input;
        self
    }
    /// <p>The name of a database that <code>DbUser</code> is authorized to log on to. If <code>DbName</code> is not specified, <code>DbUser</code> can log on to any existing database.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain uppercase or lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn get_db_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_name
    }
    /// <p>The unique identifier of the cluster that contains the database for which you are requesting credentials. This parameter is case sensitive.</p>
    pub fn cluster_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the cluster that contains the database for which you are requesting credentials. This parameter is case sensitive.</p>
    pub fn set_cluster_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_identifier = input;
        self
    }
    /// <p>The unique identifier of the cluster that contains the database for which you are requesting credentials. This parameter is case sensitive.</p>
    pub fn get_cluster_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_identifier
    }
    /// <p>The number of seconds until the returned temporary password expires.</p>
    /// <p>Constraint: minimum 900, maximum 3600.</p>
    /// <p>Default: 900</p>
    pub fn duration_seconds(mut self, input: i32) -> Self {
        self.duration_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds until the returned temporary password expires.</p>
    /// <p>Constraint: minimum 900, maximum 3600.</p>
    /// <p>Default: 900</p>
    pub fn set_duration_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.duration_seconds = input;
        self
    }
    /// <p>The number of seconds until the returned temporary password expires.</p>
    /// <p>Constraint: minimum 900, maximum 3600.</p>
    /// <p>Default: 900</p>
    pub fn get_duration_seconds(&self) -> &::std::option::Option<i32> {
        &self.duration_seconds
    }
    /// <p>Create a database user with the name specified for the user named in <code>DbUser</code> if one does not exist.</p>
    pub fn auto_create(mut self, input: bool) -> Self {
        self.auto_create = ::std::option::Option::Some(input);
        self
    }
    /// <p>Create a database user with the name specified for the user named in <code>DbUser</code> if one does not exist.</p>
    pub fn set_auto_create(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_create = input;
        self
    }
    /// <p>Create a database user with the name specified for the user named in <code>DbUser</code> if one does not exist.</p>
    pub fn get_auto_create(&self) -> &::std::option::Option<bool> {
        &self.auto_create
    }
    /// Appends an item to `db_groups`.
    ///
    /// To override the contents of this collection use [`set_db_groups`](Self::set_db_groups).
    ///
    /// <p>A list of the names of existing database groups that the user named in <code>DbUser</code> will join for the current session, in addition to any group memberships for an existing user. If not specified, a new user is added only to PUBLIC.</p>
    /// <p>Database group name constraints</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain only lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn db_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.db_groups.unwrap_or_default();
        v.push(input.into());
        self.db_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the names of existing database groups that the user named in <code>DbUser</code> will join for the current session, in addition to any group memberships for an existing user. If not specified, a new user is added only to PUBLIC.</p>
    /// <p>Database group name constraints</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain only lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn set_db_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.db_groups = input;
        self
    }
    /// <p>A list of the names of existing database groups that the user named in <code>DbUser</code> will join for the current session, in addition to any group memberships for an existing user. If not specified, a new user is added only to PUBLIC.</p>
    /// <p>Database group name constraints</p>
    /// <ul>
    /// <li>
    /// <p>Must be 1 to 64 alphanumeric characters or hyphens</p></li>
    /// <li>
    /// <p>Must contain only lowercase letters, numbers, underscore, plus sign, period (dot), at symbol (@), or hyphen.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Must not contain a colon ( : ) or slash ( / ).</p></li>
    /// <li>
    /// <p>Cannot be a reserved word. A list of reserved words can be found in <a href="http://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p></li>
    /// </ul>
    pub fn get_db_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.db_groups
    }
    /// <p>The custom domain name for the cluster credentials.</p>
    pub fn custom_domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom domain name for the cluster credentials.</p>
    pub fn set_custom_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_domain_name = input;
        self
    }
    /// <p>The custom domain name for the cluster credentials.</p>
    pub fn get_custom_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_domain_name
    }
    /// Consumes the builder and constructs a [`GetClusterCredentialsInput`](crate::operation::get_cluster_credentials::GetClusterCredentialsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_cluster_credentials::GetClusterCredentialsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_cluster_credentials::GetClusterCredentialsInput {
            db_user: self.db_user,
            db_name: self.db_name,
            cluster_identifier: self.cluster_identifier,
            duration_seconds: self.duration_seconds,
            auto_create: self.auto_create,
            db_groups: self.db_groups,
            custom_domain_name: self.custom_domain_name,
        })
    }
}
