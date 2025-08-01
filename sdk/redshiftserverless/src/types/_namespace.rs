// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A collection of database objects and users.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct Namespace {
    /// <p>The Amazon Resource Name (ARN) associated with a namespace.</p>
    pub namespace_arn: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of a namespace.</p>
    pub namespace_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the namespace. Must be between 3-64 alphanumeric characters in lowercase, and it cannot be a reserved word. A list of reserved words can be found in <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p>
    pub namespace_name: ::std::option::Option<::std::string::String>,
    /// <p>The username of the administrator for the first database created in the namespace.</p>
    pub admin_username: ::std::option::Option<::std::string::String>,
    /// <p>The name of the first database created in the namespace.</p>
    pub db_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services Key Management Service key used to encrypt your data.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role to set as a default in the namespace.</p>
    pub default_iam_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of IAM roles to associate with the namespace.</p>
    pub iam_roles: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The types of logs the namespace can export. Available export types are User log, Connection log, and User activity log.</p>
    pub log_exports: ::std::option::Option<::std::vec::Vec<crate::types::LogExport>>,
    /// <p>The status of the namespace.</p>
    pub status: ::std::option::Option<crate::types::NamespaceStatus>,
    /// <p>The date of when the namespace was created.</p>
    pub creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub admin_password_secret_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub admin_password_secret_kms_key_id: ::std::option::Option<::std::string::String>,
}
impl Namespace {
    /// <p>The Amazon Resource Name (ARN) associated with a namespace.</p>
    pub fn namespace_arn(&self) -> ::std::option::Option<&str> {
        self.namespace_arn.as_deref()
    }
    /// <p>The unique identifier of a namespace.</p>
    pub fn namespace_id(&self) -> ::std::option::Option<&str> {
        self.namespace_id.as_deref()
    }
    /// <p>The name of the namespace. Must be between 3-64 alphanumeric characters in lowercase, and it cannot be a reserved word. A list of reserved words can be found in <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p>
    pub fn namespace_name(&self) -> ::std::option::Option<&str> {
        self.namespace_name.as_deref()
    }
    /// <p>The username of the administrator for the first database created in the namespace.</p>
    pub fn admin_username(&self) -> ::std::option::Option<&str> {
        self.admin_username.as_deref()
    }
    /// <p>The name of the first database created in the namespace.</p>
    pub fn db_name(&self) -> ::std::option::Option<&str> {
        self.db_name.as_deref()
    }
    /// <p>The ID of the Amazon Web Services Key Management Service key used to encrypt your data.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to set as a default in the namespace.</p>
    pub fn default_iam_role_arn(&self) -> ::std::option::Option<&str> {
        self.default_iam_role_arn.as_deref()
    }
    /// <p>A list of IAM roles to associate with the namespace.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.iam_roles.is_none()`.
    pub fn iam_roles(&self) -> &[::std::string::String] {
        self.iam_roles.as_deref().unwrap_or_default()
    }
    /// <p>The types of logs the namespace can export. Available export types are User log, Connection log, and User activity log.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.log_exports.is_none()`.
    pub fn log_exports(&self) -> &[crate::types::LogExport] {
        self.log_exports.as_deref().unwrap_or_default()
    }
    /// <p>The status of the namespace.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::NamespaceStatus> {
        self.status.as_ref()
    }
    /// <p>The date of when the namespace was created.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn admin_password_secret_arn(&self) -> ::std::option::Option<&str> {
        self.admin_password_secret_arn.as_deref()
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn admin_password_secret_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.admin_password_secret_kms_key_id.as_deref()
    }
}
impl ::std::fmt::Debug for Namespace {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("Namespace");
        formatter.field("namespace_arn", &self.namespace_arn);
        formatter.field("namespace_id", &self.namespace_id);
        formatter.field("namespace_name", &self.namespace_name);
        formatter.field("admin_username", &"*** Sensitive Data Redacted ***");
        formatter.field("db_name", &self.db_name);
        formatter.field("kms_key_id", &self.kms_key_id);
        formatter.field("default_iam_role_arn", &self.default_iam_role_arn);
        formatter.field("iam_roles", &self.iam_roles);
        formatter.field("log_exports", &self.log_exports);
        formatter.field("status", &self.status);
        formatter.field("creation_date", &self.creation_date);
        formatter.field("admin_password_secret_arn", &self.admin_password_secret_arn);
        formatter.field("admin_password_secret_kms_key_id", &self.admin_password_secret_kms_key_id);
        formatter.finish()
    }
}
impl Namespace {
    /// Creates a new builder-style object to manufacture [`Namespace`](crate::types::Namespace).
    pub fn builder() -> crate::types::builders::NamespaceBuilder {
        crate::types::builders::NamespaceBuilder::default()
    }
}

/// A builder for [`Namespace`](crate::types::Namespace).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct NamespaceBuilder {
    pub(crate) namespace_arn: ::std::option::Option<::std::string::String>,
    pub(crate) namespace_id: ::std::option::Option<::std::string::String>,
    pub(crate) namespace_name: ::std::option::Option<::std::string::String>,
    pub(crate) admin_username: ::std::option::Option<::std::string::String>,
    pub(crate) db_name: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) default_iam_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) iam_roles: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) log_exports: ::std::option::Option<::std::vec::Vec<crate::types::LogExport>>,
    pub(crate) status: ::std::option::Option<crate::types::NamespaceStatus>,
    pub(crate) creation_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) admin_password_secret_arn: ::std::option::Option<::std::string::String>,
    pub(crate) admin_password_secret_kms_key_id: ::std::option::Option<::std::string::String>,
}
impl NamespaceBuilder {
    /// <p>The Amazon Resource Name (ARN) associated with a namespace.</p>
    pub fn namespace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with a namespace.</p>
    pub fn set_namespace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) associated with a namespace.</p>
    pub fn get_namespace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_arn
    }
    /// <p>The unique identifier of a namespace.</p>
    pub fn namespace_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of a namespace.</p>
    pub fn set_namespace_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_id = input;
        self
    }
    /// <p>The unique identifier of a namespace.</p>
    pub fn get_namespace_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_id
    }
    /// <p>The name of the namespace. Must be between 3-64 alphanumeric characters in lowercase, and it cannot be a reserved word. A list of reserved words can be found in <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p>
    pub fn namespace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.namespace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the namespace. Must be between 3-64 alphanumeric characters in lowercase, and it cannot be a reserved word. A list of reserved words can be found in <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p>
    pub fn set_namespace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.namespace_name = input;
        self
    }
    /// <p>The name of the namespace. Must be between 3-64 alphanumeric characters in lowercase, and it cannot be a reserved word. A list of reserved words can be found in <a href="https://docs.aws.amazon.com/redshift/latest/dg/r_pg_keywords.html">Reserved Words</a> in the Amazon Redshift Database Developer Guide.</p>
    pub fn get_namespace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.namespace_name
    }
    /// <p>The username of the administrator for the first database created in the namespace.</p>
    pub fn admin_username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The username of the administrator for the first database created in the namespace.</p>
    pub fn set_admin_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_username = input;
        self
    }
    /// <p>The username of the administrator for the first database created in the namespace.</p>
    pub fn get_admin_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_username
    }
    /// <p>The name of the first database created in the namespace.</p>
    pub fn db_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the first database created in the namespace.</p>
    pub fn set_db_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_name = input;
        self
    }
    /// <p>The name of the first database created in the namespace.</p>
    pub fn get_db_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_name
    }
    /// <p>The ID of the Amazon Web Services Key Management Service key used to encrypt your data.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services Key Management Service key used to encrypt your data.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The ID of the Amazon Web Services Key Management Service key used to encrypt your data.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to set as a default in the namespace.</p>
    pub fn default_iam_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_iam_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to set as a default in the namespace.</p>
    pub fn set_default_iam_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_iam_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role to set as a default in the namespace.</p>
    pub fn get_default_iam_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_iam_role_arn
    }
    /// Appends an item to `iam_roles`.
    ///
    /// To override the contents of this collection use [`set_iam_roles`](Self::set_iam_roles).
    ///
    /// <p>A list of IAM roles to associate with the namespace.</p>
    pub fn iam_roles(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.iam_roles.unwrap_or_default();
        v.push(input.into());
        self.iam_roles = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of IAM roles to associate with the namespace.</p>
    pub fn set_iam_roles(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.iam_roles = input;
        self
    }
    /// <p>A list of IAM roles to associate with the namespace.</p>
    pub fn get_iam_roles(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.iam_roles
    }
    /// Appends an item to `log_exports`.
    ///
    /// To override the contents of this collection use [`set_log_exports`](Self::set_log_exports).
    ///
    /// <p>The types of logs the namespace can export. Available export types are User log, Connection log, and User activity log.</p>
    pub fn log_exports(mut self, input: crate::types::LogExport) -> Self {
        let mut v = self.log_exports.unwrap_or_default();
        v.push(input);
        self.log_exports = ::std::option::Option::Some(v);
        self
    }
    /// <p>The types of logs the namespace can export. Available export types are User log, Connection log, and User activity log.</p>
    pub fn set_log_exports(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LogExport>>) -> Self {
        self.log_exports = input;
        self
    }
    /// <p>The types of logs the namespace can export. Available export types are User log, Connection log, and User activity log.</p>
    pub fn get_log_exports(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LogExport>> {
        &self.log_exports
    }
    /// <p>The status of the namespace.</p>
    pub fn status(mut self, input: crate::types::NamespaceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the namespace.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::NamespaceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the namespace.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::NamespaceStatus> {
        &self.status
    }
    /// <p>The date of when the namespace was created.</p>
    pub fn creation_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date of when the namespace was created.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The date of when the namespace was created.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn admin_password_secret_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_password_secret_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn set_admin_password_secret_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_password_secret_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the namespace's admin user credentials secret.</p>
    pub fn get_admin_password_secret_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_password_secret_arn
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn admin_password_secret_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.admin_password_secret_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn set_admin_password_secret_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.admin_password_secret_kms_key_id = input;
        self
    }
    /// <p>The ID of the Key Management Service (KMS) key used to encrypt and store the namespace's admin credentials secret.</p>
    pub fn get_admin_password_secret_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.admin_password_secret_kms_key_id
    }
    /// Consumes the builder and constructs a [`Namespace`](crate::types::Namespace).
    pub fn build(self) -> crate::types::Namespace {
        crate::types::Namespace {
            namespace_arn: self.namespace_arn,
            namespace_id: self.namespace_id,
            namespace_name: self.namespace_name,
            admin_username: self.admin_username,
            db_name: self.db_name,
            kms_key_id: self.kms_key_id,
            default_iam_role_arn: self.default_iam_role_arn,
            iam_roles: self.iam_roles,
            log_exports: self.log_exports,
            status: self.status,
            creation_date: self.creation_date,
            admin_password_secret_arn: self.admin_password_secret_arn,
            admin_password_secret_kms_key_id: self.admin_password_secret_kms_key_id,
        }
    }
}
impl ::std::fmt::Debug for NamespaceBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("NamespaceBuilder");
        formatter.field("namespace_arn", &self.namespace_arn);
        formatter.field("namespace_id", &self.namespace_id);
        formatter.field("namespace_name", &self.namespace_name);
        formatter.field("admin_username", &"*** Sensitive Data Redacted ***");
        formatter.field("db_name", &self.db_name);
        formatter.field("kms_key_id", &self.kms_key_id);
        formatter.field("default_iam_role_arn", &self.default_iam_role_arn);
        formatter.field("iam_roles", &self.iam_roles);
        formatter.field("log_exports", &self.log_exports);
        formatter.field("status", &self.status);
        formatter.field("creation_date", &self.creation_date);
        formatter.field("admin_password_secret_arn", &self.admin_password_secret_arn);
        formatter.field("admin_password_secret_kms_key_id", &self.admin_password_secret_kms_key_id);
        formatter.finish()
    }
}
