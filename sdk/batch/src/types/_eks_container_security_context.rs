// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The security context for a job. For more information, see <a href="https://kubernetes.io/docs/tasks/configure-pod-container/security-context/">Configure a security context for a pod or container</a> in the <i>Kubernetes documentation</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EksContainerSecurityContext {
    /// <p>When this parameter is specified, the container is run as the specified user ID (<code>uid</code>). If this parameter isn't specified, the default is the user that's specified in the image metadata. This parameter maps to <code>RunAsUser</code> and <code>MustRanAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub run_as_user: ::std::option::Option<i64>,
    /// <p>When this parameter is specified, the container is run as the specified group ID (<code>gid</code>). If this parameter isn't specified, the default is the group that's specified in the image metadata. This parameter maps to <code>RunAsGroup</code> and <code>MustRunAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub run_as_group: ::std::option::Option<i64>,
    /// <p>When this parameter is <code>true</code>, the container is given elevated permissions on the host container instance. The level of permissions are similar to the <code>root</code> user permissions. The default value is <code>false</code>. This parameter maps to <code>privileged</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#privileged">Privileged pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub privileged: ::std::option::Option<bool>,
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process. The default value is <code>false</code>.</p>
    pub allow_privilege_escalation: ::std::option::Option<bool>,
    /// <p>When this parameter is <code>true</code>, the container is given read-only access to its root file system. The default value is <code>false</code>. This parameter maps to <code>ReadOnlyRootFilesystem</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#volumes-and-file-systems">Volumes and file systems pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub read_only_root_filesystem: ::std::option::Option<bool>,
    /// <p>When this parameter is specified, the container is run as a user with a <code>uid</code> other than 0. If this parameter isn't specified, so such rule is enforced. This parameter maps to <code>RunAsUser</code> and <code>MustRunAsNonRoot</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub run_as_non_root: ::std::option::Option<bool>,
}
impl EksContainerSecurityContext {
    /// <p>When this parameter is specified, the container is run as the specified user ID (<code>uid</code>). If this parameter isn't specified, the default is the user that's specified in the image metadata. This parameter maps to <code>RunAsUser</code> and <code>MustRanAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_user(&self) -> ::std::option::Option<i64> {
        self.run_as_user
    }
    /// <p>When this parameter is specified, the container is run as the specified group ID (<code>gid</code>). If this parameter isn't specified, the default is the group that's specified in the image metadata. This parameter maps to <code>RunAsGroup</code> and <code>MustRunAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_group(&self) -> ::std::option::Option<i64> {
        self.run_as_group
    }
    /// <p>When this parameter is <code>true</code>, the container is given elevated permissions on the host container instance. The level of permissions are similar to the <code>root</code> user permissions. The default value is <code>false</code>. This parameter maps to <code>privileged</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#privileged">Privileged pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn privileged(&self) -> ::std::option::Option<bool> {
        self.privileged
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process. The default value is <code>false</code>.</p>
    pub fn allow_privilege_escalation(&self) -> ::std::option::Option<bool> {
        self.allow_privilege_escalation
    }
    /// <p>When this parameter is <code>true</code>, the container is given read-only access to its root file system. The default value is <code>false</code>. This parameter maps to <code>ReadOnlyRootFilesystem</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#volumes-and-file-systems">Volumes and file systems pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn read_only_root_filesystem(&self) -> ::std::option::Option<bool> {
        self.read_only_root_filesystem
    }
    /// <p>When this parameter is specified, the container is run as a user with a <code>uid</code> other than 0. If this parameter isn't specified, so such rule is enforced. This parameter maps to <code>RunAsUser</code> and <code>MustRunAsNonRoot</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_non_root(&self) -> ::std::option::Option<bool> {
        self.run_as_non_root
    }
}
impl EksContainerSecurityContext {
    /// Creates a new builder-style object to manufacture [`EksContainerSecurityContext`](crate::types::EksContainerSecurityContext).
    pub fn builder() -> crate::types::builders::EksContainerSecurityContextBuilder {
        crate::types::builders::EksContainerSecurityContextBuilder::default()
    }
}

/// A builder for [`EksContainerSecurityContext`](crate::types::EksContainerSecurityContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EksContainerSecurityContextBuilder {
    pub(crate) run_as_user: ::std::option::Option<i64>,
    pub(crate) run_as_group: ::std::option::Option<i64>,
    pub(crate) privileged: ::std::option::Option<bool>,
    pub(crate) allow_privilege_escalation: ::std::option::Option<bool>,
    pub(crate) read_only_root_filesystem: ::std::option::Option<bool>,
    pub(crate) run_as_non_root: ::std::option::Option<bool>,
}
impl EksContainerSecurityContextBuilder {
    /// <p>When this parameter is specified, the container is run as the specified user ID (<code>uid</code>). If this parameter isn't specified, the default is the user that's specified in the image metadata. This parameter maps to <code>RunAsUser</code> and <code>MustRanAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_user(mut self, input: i64) -> Self {
        self.run_as_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this parameter is specified, the container is run as the specified user ID (<code>uid</code>). If this parameter isn't specified, the default is the user that's specified in the image metadata. This parameter maps to <code>RunAsUser</code> and <code>MustRanAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_run_as_user(mut self, input: ::std::option::Option<i64>) -> Self {
        self.run_as_user = input;
        self
    }
    /// <p>When this parameter is specified, the container is run as the specified user ID (<code>uid</code>). If this parameter isn't specified, the default is the user that's specified in the image metadata. This parameter maps to <code>RunAsUser</code> and <code>MustRanAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_run_as_user(&self) -> &::std::option::Option<i64> {
        &self.run_as_user
    }
    /// <p>When this parameter is specified, the container is run as the specified group ID (<code>gid</code>). If this parameter isn't specified, the default is the group that's specified in the image metadata. This parameter maps to <code>RunAsGroup</code> and <code>MustRunAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_group(mut self, input: i64) -> Self {
        self.run_as_group = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this parameter is specified, the container is run as the specified group ID (<code>gid</code>). If this parameter isn't specified, the default is the group that's specified in the image metadata. This parameter maps to <code>RunAsGroup</code> and <code>MustRunAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_run_as_group(mut self, input: ::std::option::Option<i64>) -> Self {
        self.run_as_group = input;
        self
    }
    /// <p>When this parameter is specified, the container is run as the specified group ID (<code>gid</code>). If this parameter isn't specified, the default is the group that's specified in the image metadata. This parameter maps to <code>RunAsGroup</code> and <code>MustRunAs</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_run_as_group(&self) -> &::std::option::Option<i64> {
        &self.run_as_group
    }
    /// <p>When this parameter is <code>true</code>, the container is given elevated permissions on the host container instance. The level of permissions are similar to the <code>root</code> user permissions. The default value is <code>false</code>. This parameter maps to <code>privileged</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#privileged">Privileged pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn privileged(mut self, input: bool) -> Self {
        self.privileged = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this parameter is <code>true</code>, the container is given elevated permissions on the host container instance. The level of permissions are similar to the <code>root</code> user permissions. The default value is <code>false</code>. This parameter maps to <code>privileged</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#privileged">Privileged pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_privileged(mut self, input: ::std::option::Option<bool>) -> Self {
        self.privileged = input;
        self
    }
    /// <p>When this parameter is <code>true</code>, the container is given elevated permissions on the host container instance. The level of permissions are similar to the <code>root</code> user permissions. The default value is <code>false</code>. This parameter maps to <code>privileged</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#privileged">Privileged pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_privileged(&self) -> &::std::option::Option<bool> {
        &self.privileged
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process. The default value is <code>false</code>.</p>
    pub fn allow_privilege_escalation(mut self, input: bool) -> Self {
        self.allow_privilege_escalation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process. The default value is <code>false</code>.</p>
    pub fn set_allow_privilege_escalation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_privilege_escalation = input;
        self
    }
    /// <p>Whether or not a container or a Kubernetes pod is allowed to gain more privileges than its parent process. The default value is <code>false</code>.</p>
    pub fn get_allow_privilege_escalation(&self) -> &::std::option::Option<bool> {
        &self.allow_privilege_escalation
    }
    /// <p>When this parameter is <code>true</code>, the container is given read-only access to its root file system. The default value is <code>false</code>. This parameter maps to <code>ReadOnlyRootFilesystem</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#volumes-and-file-systems">Volumes and file systems pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn read_only_root_filesystem(mut self, input: bool) -> Self {
        self.read_only_root_filesystem = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this parameter is <code>true</code>, the container is given read-only access to its root file system. The default value is <code>false</code>. This parameter maps to <code>ReadOnlyRootFilesystem</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#volumes-and-file-systems">Volumes and file systems pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_read_only_root_filesystem(mut self, input: ::std::option::Option<bool>) -> Self {
        self.read_only_root_filesystem = input;
        self
    }
    /// <p>When this parameter is <code>true</code>, the container is given read-only access to its root file system. The default value is <code>false</code>. This parameter maps to <code>ReadOnlyRootFilesystem</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#volumes-and-file-systems">Volumes and file systems pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_read_only_root_filesystem(&self) -> &::std::option::Option<bool> {
        &self.read_only_root_filesystem
    }
    /// <p>When this parameter is specified, the container is run as a user with a <code>uid</code> other than 0. If this parameter isn't specified, so such rule is enforced. This parameter maps to <code>RunAsUser</code> and <code>MustRunAsNonRoot</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn run_as_non_root(mut self, input: bool) -> Self {
        self.run_as_non_root = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this parameter is specified, the container is run as a user with a <code>uid</code> other than 0. If this parameter isn't specified, so such rule is enforced. This parameter maps to <code>RunAsUser</code> and <code>MustRunAsNonRoot</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_run_as_non_root(mut self, input: ::std::option::Option<bool>) -> Self {
        self.run_as_non_root = input;
        self
    }
    /// <p>When this parameter is specified, the container is run as a user with a <code>uid</code> other than 0. If this parameter isn't specified, so such rule is enforced. This parameter maps to <code>RunAsUser</code> and <code>MustRunAsNonRoot</code> policy in the <a href="https://kubernetes.io/docs/concepts/security/pod-security-policy/#users-and-groups">Users and groups pod security policies</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_run_as_non_root(&self) -> &::std::option::Option<bool> {
        &self.run_as_non_root
    }
    /// Consumes the builder and constructs a [`EksContainerSecurityContext`](crate::types::EksContainerSecurityContext).
    pub fn build(self) -> crate::types::EksContainerSecurityContext {
        crate::types::EksContainerSecurityContext {
            run_as_user: self.run_as_user,
            run_as_group: self.run_as_group,
            privileged: self.privileged,
            allow_privilege_escalation: self.allow_privilege_escalation,
            read_only_root_filesystem: self.read_only_root_filesystem,
            run_as_non_root: self.run_as_non_root,
        }
    }
}
