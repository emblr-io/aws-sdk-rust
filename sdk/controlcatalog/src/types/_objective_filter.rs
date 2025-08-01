// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An optional filter that narrows the list of objectives to a specific domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectiveFilter {
    /// <p>The domain that's used as filter criteria.</p>
    /// <p>You can use this parameter to specify one domain ARN at a time. Passing multiple ARNs in the <code>ObjectiveFilter</code> isn’t supported.</p>
    pub domains: ::std::option::Option<::std::vec::Vec<crate::types::DomainResourceFilter>>,
}
impl ObjectiveFilter {
    /// <p>The domain that's used as filter criteria.</p>
    /// <p>You can use this parameter to specify one domain ARN at a time. Passing multiple ARNs in the <code>ObjectiveFilter</code> isn’t supported.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domains.is_none()`.
    pub fn domains(&self) -> &[crate::types::DomainResourceFilter] {
        self.domains.as_deref().unwrap_or_default()
    }
}
impl ObjectiveFilter {
    /// Creates a new builder-style object to manufacture [`ObjectiveFilter`](crate::types::ObjectiveFilter).
    pub fn builder() -> crate::types::builders::ObjectiveFilterBuilder {
        crate::types::builders::ObjectiveFilterBuilder::default()
    }
}

/// A builder for [`ObjectiveFilter`](crate::types::ObjectiveFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectiveFilterBuilder {
    pub(crate) domains: ::std::option::Option<::std::vec::Vec<crate::types::DomainResourceFilter>>,
}
impl ObjectiveFilterBuilder {
    /// Appends an item to `domains`.
    ///
    /// To override the contents of this collection use [`set_domains`](Self::set_domains).
    ///
    /// <p>The domain that's used as filter criteria.</p>
    /// <p>You can use this parameter to specify one domain ARN at a time. Passing multiple ARNs in the <code>ObjectiveFilter</code> isn’t supported.</p>
    pub fn domains(mut self, input: crate::types::DomainResourceFilter) -> Self {
        let mut v = self.domains.unwrap_or_default();
        v.push(input);
        self.domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The domain that's used as filter criteria.</p>
    /// <p>You can use this parameter to specify one domain ARN at a time. Passing multiple ARNs in the <code>ObjectiveFilter</code> isn’t supported.</p>
    pub fn set_domains(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DomainResourceFilter>>) -> Self {
        self.domains = input;
        self
    }
    /// <p>The domain that's used as filter criteria.</p>
    /// <p>You can use this parameter to specify one domain ARN at a time. Passing multiple ARNs in the <code>ObjectiveFilter</code> isn’t supported.</p>
    pub fn get_domains(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DomainResourceFilter>> {
        &self.domains
    }
    /// Consumes the builder and constructs a [`ObjectiveFilter`](crate::types::ObjectiveFilter).
    pub fn build(self) -> crate::types::ObjectiveFilter {
        crate::types::ObjectiveFilter { domains: self.domains }
    }
}
