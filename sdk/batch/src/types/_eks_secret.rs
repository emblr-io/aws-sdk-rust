// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the configuration of a Kubernetes <code>secret</code> volume. For more information, see <a href="https://kubernetes.io/docs/concepts/storage/volumes/#secret">secret</a> in the <i>Kubernetes documentation</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EksSecret {
    /// <p>The name of the secret. The name must be allowed as a DNS subdomain name. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names">DNS subdomain names</a> in the <i>Kubernetes documentation</i>.</p>
    pub secret_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the secret or the secret's keys must be defined.</p>
    pub optional: ::std::option::Option<bool>,
}
impl EksSecret {
    /// <p>The name of the secret. The name must be allowed as a DNS subdomain name. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names">DNS subdomain names</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn secret_name(&self) -> ::std::option::Option<&str> {
        self.secret_name.as_deref()
    }
    /// <p>Specifies whether the secret or the secret's keys must be defined.</p>
    pub fn optional(&self) -> ::std::option::Option<bool> {
        self.optional
    }
}
impl EksSecret {
    /// Creates a new builder-style object to manufacture [`EksSecret`](crate::types::EksSecret).
    pub fn builder() -> crate::types::builders::EksSecretBuilder {
        crate::types::builders::EksSecretBuilder::default()
    }
}

/// A builder for [`EksSecret`](crate::types::EksSecret).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EksSecretBuilder {
    pub(crate) secret_name: ::std::option::Option<::std::string::String>,
    pub(crate) optional: ::std::option::Option<bool>,
}
impl EksSecretBuilder {
    /// <p>The name of the secret. The name must be allowed as a DNS subdomain name. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names">DNS subdomain names</a> in the <i>Kubernetes documentation</i>.</p>
    /// This field is required.
    pub fn secret_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secret_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the secret. The name must be allowed as a DNS subdomain name. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names">DNS subdomain names</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_secret_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secret_name = input;
        self
    }
    /// <p>The name of the secret. The name must be allowed as a DNS subdomain name. For more information, see <a href="https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names">DNS subdomain names</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_secret_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.secret_name
    }
    /// <p>Specifies whether the secret or the secret's keys must be defined.</p>
    pub fn optional(mut self, input: bool) -> Self {
        self.optional = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the secret or the secret's keys must be defined.</p>
    pub fn set_optional(mut self, input: ::std::option::Option<bool>) -> Self {
        self.optional = input;
        self
    }
    /// <p>Specifies whether the secret or the secret's keys must be defined.</p>
    pub fn get_optional(&self) -> &::std::option::Option<bool> {
        &self.optional
    }
    /// Consumes the builder and constructs a [`EksSecret`](crate::types::EksSecret).
    pub fn build(self) -> crate::types::EksSecret {
        crate::types::EksSecret {
            secret_name: self.secret_name,
            optional: self.optional,
        }
    }
}
