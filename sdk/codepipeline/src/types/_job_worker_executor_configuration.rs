// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the polling configuration for the <code>JobWorker</code> action engine, or executor.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobWorkerExecutorConfiguration {
    /// <p>The accounts in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub polling_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The service Principals in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub polling_service_principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl JobWorkerExecutorConfiguration {
    /// <p>The accounts in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.polling_accounts.is_none()`.
    pub fn polling_accounts(&self) -> &[::std::string::String] {
        self.polling_accounts.as_deref().unwrap_or_default()
    }
    /// <p>The service Principals in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.polling_service_principals.is_none()`.
    pub fn polling_service_principals(&self) -> &[::std::string::String] {
        self.polling_service_principals.as_deref().unwrap_or_default()
    }
}
impl JobWorkerExecutorConfiguration {
    /// Creates a new builder-style object to manufacture [`JobWorkerExecutorConfiguration`](crate::types::JobWorkerExecutorConfiguration).
    pub fn builder() -> crate::types::builders::JobWorkerExecutorConfigurationBuilder {
        crate::types::builders::JobWorkerExecutorConfigurationBuilder::default()
    }
}

/// A builder for [`JobWorkerExecutorConfiguration`](crate::types::JobWorkerExecutorConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobWorkerExecutorConfigurationBuilder {
    pub(crate) polling_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) polling_service_principals: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl JobWorkerExecutorConfigurationBuilder {
    /// Appends an item to `polling_accounts`.
    ///
    /// To override the contents of this collection use [`set_polling_accounts`](Self::set_polling_accounts).
    ///
    /// <p>The accounts in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn polling_accounts(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.polling_accounts.unwrap_or_default();
        v.push(input.into());
        self.polling_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The accounts in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn set_polling_accounts(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.polling_accounts = input;
        self
    }
    /// <p>The accounts in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn get_polling_accounts(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.polling_accounts
    }
    /// Appends an item to `polling_service_principals`.
    ///
    /// To override the contents of this collection use [`set_polling_service_principals`](Self::set_polling_service_principals).
    ///
    /// <p>The service Principals in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn polling_service_principals(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.polling_service_principals.unwrap_or_default();
        v.push(input.into());
        self.polling_service_principals = ::std::option::Option::Some(v);
        self
    }
    /// <p>The service Principals in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn set_polling_service_principals(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.polling_service_principals = input;
        self
    }
    /// <p>The service Principals in which the job worker is configured and might poll for jobs as part of the action execution.</p>
    pub fn get_polling_service_principals(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.polling_service_principals
    }
    /// Consumes the builder and constructs a [`JobWorkerExecutorConfiguration`](crate::types::JobWorkerExecutorConfiguration).
    pub fn build(self) -> crate::types::JobWorkerExecutorConfiguration {
        crate::types::JobWorkerExecutorConfiguration {
            polling_accounts: self.polling_accounts,
            polling_service_principals: self.polling_service_principals,
        }
    }
}
