package security_log

import (
	"fmt"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events
type SecurityLog struct {
	schema.CommonFields

	// Common field for all events
	Timestamp  *time.Time `json:"timestamp"`
	DocumentId *string    `json:"document_id"`
	Action     *string    `json:"action"`

	// Present in: 1/334 events – actions_cache.delete
	ActionsCacheId *string `json:"actions_cache_id,omitempty"`

	// Present in: 1/334 events – actions_cache.delete
	ActionsCacheKey *string `json:"actions_cache_key,omitempty"`

	// Present in: 1/334 events – actions_cache.delete
	ActionsCacheScope *string `json:"actions_cache_scope,omitempty"`

	// Present in: 1/334 events – actions_cache.delete
	ActionsCacheVersion *string `json:"actions_cache_version,omitempty"`

	// Present in: 2/334 events – hook.active_changed, sponsors.sponsor_sponsorship_payment_complete
	Active *string `json:"active,omitempty"`

	// Present in: 1/334 events – hook.active_changed
	ActiveWas *string `json:"active_was,omitempty"`

	// Present in: 324/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.remove, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	Actor *string `json:"actor,omitempty"`

	// Present in: 326/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.remove, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	ActorId *int64 `json:"actor_id,omitempty"`

	// Present in: 33/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, codespaces.connect, codespaces.create, environment.create_actions_variable, environment.delete, integration_installation.repositories_added, integration_installation.repositories_removed, migration.create, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, project_collaborator.add, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.change_merge_setting, repo.create, repo.destroy, repo.update_actions_settings, repo.update_default_branch, repo.update_member, repository_ruleset.update, user_email.confirm_claim, workflows.disable_workflow, workflows.pin_workflow, workflows.unpin_workflow
	ActorIsBot *bool `json:"actor_is_bot,omitempty"`

	// Present in: 11/334 events – integration.create, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.version_updated
	ApplicationClientId *string `json:"application_client_id,omitempty"`

	// Present in: 1/334 events – environment.update_protection_rule
	Approvers *string `json:"approvers,omitempty"`

	// Present in: 1/334 events – environment.update_protection_rule
	ApproversWas *string `json:"approvers_was,omitempty"`

	// Present in: 2/334 events – user.block_user, user.unblock_user
	BlockedUser *string `json:"blocked_user,omitempty"`

	// Present in: 1/334 events – repo.code_scanning_configuration_for_branch_deleted
	Branch *string `json:"branch,omitempty"`

	// Present in: 50/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, environment.create_actions_secret, environment.create_actions_variable, environment.remove_actions_secret, oauth_authorization.create, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.update_member_repository_invitation_permission, project.rename, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.code_scanning_configuration_for_branch_deleted, repo.create, repo.create_actions_variable, repo.remove_actions_variable, repo.remove_member, repo.remove_topic, repo.set_actions_fork_pr_approvals_policy, repo.temporary_access_granted, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_variable, repository_ruleset.create, repository_ruleset.update, user_email.confirm_claim, workflows.approve_workflow_job, workflows.pin_workflow, workflows.unpin_workflow
	Business *string `json:"business,omitempty"`

	// Present in: 49/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, copilot.cfb_seat_added, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, environment.create_actions_secret, environment.create_actions_variable, environment.remove_actions_secret, oauth_authorization.create, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.update_member_repository_invitation_permission, project.rename, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.code_scanning_configuration_for_branch_deleted, repo.create, repo.create_actions_variable, repo.remove_actions_variable, repo.remove_member, repo.remove_topic, repo.set_actions_fork_pr_approvals_policy, repo.temporary_access_granted, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_variable, repository_ruleset.create, repository_ruleset.update, user_email.confirm_claim, workflows.approve_workflow_job, workflows.pin_workflow, workflows.unpin_workflow
	BusinessId *int64 `json:"business_id,omitempty"`

	// Present in: 1/334 events – environment.update_protection_rule
	CanAdminsBypass *string `json:"can_admins_bypass,omitempty"`

	// Present in: 2/334 events – repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted
	Category *string `json:"category,omitempty"`

	// Present in: 1/334 events – repo.pages_cname
	Cname *string `json:"cname,omitempty"`

	// Present in: 3/334 events – project_collaborator.add, project_collaborator.remove, project_collaborator.update
	Collaborator *string `json:"collaborator,omitempty"`

	// Present in: 3/334 events – project_collaborator.add, project_collaborator.remove, project_collaborator.update
	CollaboratorType *string `json:"collaborator_type,omitempty"`

	// Present in: 2/334 events – repository_image.create, repository_image.destroy
	ContentType *string `json:"content_type,omitempty"`

	// Present in: 333/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.remove, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.credential_revoked, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	CreatedAt *time.Time `json:"created_at,omitempty"`

	// Present in: 3/334 events – codespaces.connect, codespaces.create, codespaces.start_environment
	DevcontainerPath *string `json:"devcontainer_path,omitempty"`

	// Present in: 3/334 events – pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify
	Domain *string `json:"domain,omitempty"`

	// Present in: 5/334 events – billing.change_email, user.add_email, user.create, user.forgot_password, user.remove_email
	Email *string `json:"email,omitempty"`

	// Present in: 2/334 events – user_status.destroy, user_status.update
	Emoji *string `json:"emoji,omitempty"`

	// Present in: 4/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_overview_dashboard, org.security_center_export_code_scanning_metrics, org.security_center_export_overview_dashboard
	EndDate *time.Time `json:"end_date,omitempty"`

	// Present in: 3/334 events – environment.create_actions_variable, environment.remove_actions_variable, environment.update_actions_variable
	EnvironmentName *string `json:"environment_name,omitempty"`

	// Present in: 5/334 events – hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed
	Events []string `json:"events,omitempty"`

	// Present in: 1/334 events – hook.events_changed
	EventsWere *string `json:"events_were,omitempty"`

	// Present in: 6/334 events – git_signing_ssh_public_key.delete, oauth_access.destroy, oauth_authorization.destroy, personal_access_token.destroy, public_key.delete, public_key.unverify
	Explanation *string `json:"explanation,omitempty"`

	// Present in: 8/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk
	Filename *string `json:"filename,omitempty"`

	// Present in: 9/334 events – git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify
	Fingerprint *string `json:"fingerprint,omitempty"`

	// Present in: 3/334 events – gist.create, gist.destroy, gist.visibility_change
	GistId *string `json:"gist_id,omitempty"`

	// Present in: 4/334 events – copilot.cfb_seat_added, copilot.cfb_seat_assignment_refreshed, oauth_access.destroy, oauth_access.revoke
	HashedToken *string `json:"hashed_token,omitempty"`

	// Present in: 1/334 events – workflows.delete_workflow_run
	HeadBranch *string `json:"head_branch,omitempty"`

	// Present in: 1/334 events – workflows.delete_workflow_run
	HeadSha *string `json:"head_sha,omitempty"`

	// Present in: 5/334 events – hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed
	HookId *string `json:"hook_id,omitempty"`

	// Present in: 26/334 events – integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.delist, repo.create_integration_secret, repo.remove_integration_secret, repo.update_integration_secret, user.create_integration_secret, user.remove_integration_secret, user.update_integration_secret
	Integration *string `json:"integration,omitempty"`

	// Present in: 5/334 events – org.add_outside_collaborator, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject
	Invitee *string `json:"invitee,omitempty"`

	// Present in: 5/334 events – org.add_outside_collaborator, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject
	Inviter *string `json:"inviter,omitempty"`

	// Present in: 27/334 events – environment.create_actions_secret, environment.create_actions_variable, environment.remove_actions_secret, environment.remove_actions_variable, environment.update_actions_secret, environment.update_actions_variable, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.update_actions_secret, repo.update_actions_variable, repo.update_integration_secret, user.create_integration_secret, user.remove_integration_secret, user.update_integration_secret
	Key *string `json:"key,omitempty"`

	// Present in: 3/334 events – business.set_actions_retention_limit, org.set_actions_retention_limit, repo.set_actions_retention_limit
	Limit *string `json:"limit,omitempty"`

	// Present in: 2/334 events – user_status.destroy, user_status.update
	LimitedAvailability *string `json:"limited_availability,omitempty"`

	// Present in: 3/334 events – codespaces.connect, codespaces.create, codespaces.start_environment
	MachineType *string `json:"machine_type,omitempty"`

	// Present in: 2/334 events – integration.manager_added, integration.manager_removed
	Manager *string `json:"manager,omitempty"`

	// Present in: 6/334 events – marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject
	MarketplaceListing *string `json:"marketplace_listing,omitempty"`

	// Present in: 1/334 events – protected_branch.update_merge_queue_enforcement_level
	MergeQueueEnforcementLevel *string `json:"merge_queue_enforcement_level,omitempty"`

	// Present in: 2/334 events – user_status.destroy, user_status.update
	Message *string `json:"message,omitempty"`

	// Present in: 38/334 events – business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.start_environment, environment.add_protection_rule, environment.delete, environment.remove_protection_rule, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, protected_branch.update_merge_queue_enforcement_level, repository_ruleset.create, repository_ruleset.destroy
	Name *string `json:"name,omitempty"`

	// Present in: 1/334 events – copilot.swe_agent_repo_enablement_updated
	NewAccess *string `json:"new_access,omitempty"`

	// Present in: 1/334 events – repo.transfer_outgoing
	NewNwo *string `json:"new_nwo,omitempty"`

	// Present in: 1/334 events – repo.update_actions_settings
	NewPolicy *string `json:"new_policy,omitempty"`

	// Present in: 1/334 events – repo.update_member
	NewRepoBaseRole *string `json:"new_repo_base_role,omitempty"`

	// Present in: 1/334 events – repo.update_member
	NewRepoPermission *string `json:"new_repo_permission,omitempty"`

	// Present in: 1/334 events – environment.update_protection_rule
	NewValue *string `json:"new_value,omitempty"`

	// Present in: 2/334 events – passkey.register, passkey.remove
	Nickname *string `json:"nickname,omitempty"`

	// Present in: 12/334 events – hook.create, marketplace_listing.create, marketplace_listing.redraft, marketplace_listing.reject, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer
	OauthApplication *string `json:"oauth_application,omitempty"`

	// Present in: 34/334 events – actions_cache.delete, codespaces.export_environment, environment.create_actions_secret, environment.remove_actions_secret, environment.update_actions_secret, hook.config_changed, hook.create, hook.destroy, hook.events_changed, marketplace_listing.create, marketplace_listing.redraft, marketplace_listing.reject, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, public_key.verification_failure, repo.add_member, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.config.enable_collaborators_only, repo.create, repo.destroy, repo.update_actions_secret, repo.update_member, user.creation_rate_limit_exceeded, user.demote, user.promote, user.suspend, user.unsuspend
	OauthApplicationId *string `json:"oauth_application_id,omitempty"`

	// Present in: 6/334 events – oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update
	OauthApplicationName *string `json:"oauth_application_name,omitempty"`

	// Present in: 1/334 events – copilot.swe_agent_repo_enablement_updated
	OldAccess *string `json:"old_access,omitempty"`

	// Present in: 1/334 events – repo.update_member
	OldBaseRole *string `json:"old_base_role,omitempty"`

	// Present in: 1/334 events – repo.pages_cname
	OldCname *string `json:"old_cname,omitempty"`

	// Present in: 1/334 events – user.rename
	OldLogin *string `json:"old_login,omitempty"`

	// Present in: 3/334 events – project.rename, repo.rename, repository_ruleset.update
	OldName *string `json:"old_name,omitempty"`

	// Present in: 2/334 events – org.update_member, repo.update_member
	OldPermission *string `json:"old_permission,omitempty"`

	// Present in: 2/334 events – repo.update_actions_access_settings, repo.update_actions_settings
	OldPolicy *string `json:"old_policy,omitempty"`

	// Present in: 2/334 events – project_collaborator.add, project_collaborator.update
	OldProjectRole *string `json:"old_project_role,omitempty"`

	// Present in: 1/334 events – repo.update_member
	OldRepoBaseRole *string `json:"old_repo_base_role,omitempty"`

	// Present in: 1/334 events – repo.update_member
	OldRepoPermission *string `json:"old_repo_permission,omitempty"`

	// Present in: 1/334 events – repo.transfer
	OldUser *string `json:"old_user,omitempty"`

	// Present in: 333/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.remove, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.credential_revoked, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	OperationType *string `json:"operation_type,omitempty"`

	// Present in: 119/334 events – actions_cache.delete, billing.change_email, codespaces.start_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_protection_rule, environment.update_actions_secret, environment.update_protection_rule, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.manager_added, integration.manager_removed, marketplace_listing.change_category, marketplace_listing.delist, migration.create, oauth_application.create, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, payment_method.update, personal_access_token.request_cancelled, personal_access_token.request_denied, project.close, project.link, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_field.create, project_field.delete, project_view.create, project_view.delete, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.enable_contributors_only, repo.create, repo.create_actions_variable, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.staff_unlock, repo.transfer_outgoing, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_integration_secret, repo.update_member, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, user_status.destroy, user_status.update, workflows.pin_workflow, workflows.unpin_workflow
	Org OrganizationName `json:"org,omitempty"`

	// Present in: 121/334 events – actions_cache.delete, billing.change_email, codespaces.connect, codespaces.trusted_repositories_access_update, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_protection_rule, environment.update_actions_secret, environment.update_protection_rule, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.manager_added, integration.manager_removed, marketplace_listing.change_category, marketplace_listing.delist, migration.create, oauth_application.create, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, payment_method.update, personal_access_token.request_cancelled, personal_access_token.request_denied, project.close, project.link, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_field.create, project_field.delete, project_view.create, project_view.delete, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.enable_contributors_only, repo.create, repo.create_actions_variable, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.staff_unlock, repo.transfer_outgoing, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_integration_secret, repo.update_member, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, user.failed_login, workflows.pin_workflow, workflows.unpin_workflow
	OrgId OrganizationId `json:"org_id,omitempty"`

	// Present in: 1/334 events – codespaces.allow_permissions
	OriginRepository *string `json:"origin_repository,omitempty"`

	// Present in: 15/334 events – codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, profile_picture.update, repo.transfer
	Owner *string `json:"owner,omitempty"`

	// Present in: 6/334 events – copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify
	OwnerType *string `json:"owner_type,omitempty"`

	// Present in: 1/334 events – user.login
	PasskeyNickname *string `json:"passkey_nickname,omitempty"`

	// Present in: 2/334 events – sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy
	PatreonEmail *string `json:"patreon_email,omitempty"`

	// Present in: 2/334 events – sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy
	PatreonUsername *string `json:"patreon_username,omitempty"`

	// Present in: 5/334 events – org.add_member, org.add_outside_collaborator, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission
	Permissions map[string]string `json:"permissions,omitempty"`

	// Present in: 1/334 events – personal_access_token.request_created
	PermissionsAdded     map[string]string `json:"permissions_added,omitempty"`
	PermissionsUnchanged map[string]string `json:"permissions_unchanged,omitempty"`
	PermissionsUpgraded  map[string]string `json:"permissions_upgraded,omitempty"`

	// Present in: 10/334 events – business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_fork_pr_workflows_policy, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_fork_pr_workflows_policy, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_fork_pr_workflows_policy, repo.update_actions_access_settings
	Policy *string `json:"policy,omitempty"`

	// Present in: 1/334 events – environment.update_protection_rule
	PreventSelfReview *string `json:"prevent_self_review,omitempty"`

	// Present in: 1/334 events – repo.access
	PreviousVisibility *string `json:"previous_visibility,omitempty"`

	// Present in: 6/334 events – marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject
	PrimaryCategory *string `json:"primary_category,omitempty"`

	// Present in: 87/334 events – account.plan_change, actions_cache.delete, artifact.destroy, checks.delete_logs, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.suspend_environment, copilot.cfb_seat_added, copilot.cfb_seat_assignment_refreshed, environment.add_protection_rule, environment.create_actions_secret, environment.delete, environment.update_actions_secret, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, migration.create, oauth_access.create, oauth_access.regenerate, oauth_authorization.create, org.add_member, org.remove_member, project.update_user_permission, public_key.create, public_key.delete, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.create, repo.create_actions_secret, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_public, repo.pages_source, repo.remove_actions_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.unarchived, repo.update_actions_secret, repo.update_actions_settings, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_invitation.accept, repository_invitation.create, user.block_user, user.codespaces_trusted_repo_access_granted, user.create, user.creation_rate_limit_exceeded, user.demote, user.promote, user.remove_email, user.rename, user.suspend, user.unsuspend, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.reject_workflow_job
	ProgrammaticAccessType *string `json:"programmatic_access_type,omitempty"`

	// Present in: 5/334 events – project.close, project.open, project.visibility_private, project.visibility_public, project_collaborator.update
	ProjectId *string `json:"project_id,omitempty"`

	// Present in: 4/334 events – project.close, project.open, project.visibility_private, project.visibility_public
	ProjectKind *string `json:"project_kind,omitempty"`

	// Present in: 5/334 events – project.open, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.update
	ProjectName *string `json:"project_name,omitempty"`

	// Present in: 2/334 events – project_collaborator.add, project_collaborator.update
	ProjectRole *string `json:"project_role,omitempty"`

	// Present in: 2/334 events – project_collaborator.add, project_collaborator.update
	PublicProject *string `json:"public_project,omitempty"`

	// Present in: 46/334 events – checks.auto_trigger_enabled, codespaces.connect, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, org.add_outside_collaborator, protected_branch.update_merge_queue_enforcement_level, repo.advanced_security_enabled, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.create, repo.create_actions_variable, repo.create_integration_secret, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.remove_actions_variable, repo.remove_integration_secret, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_default_workflow_permissions, repo.set_workflow_permission_can_approve_pr, repo.temporary_access_granted, repo.transfer_outgoing, repo.update_actions_variable, repo.update_integration_secret, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, workflows.approve_workflow_job, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	PublicRepo *string `json:"public_repo,omitempty"`

	// Present in: 4/334 events – codespaces.connect, codespaces.create, codespaces.destroy, codespaces.start_environment
	PullRequestId *string `json:"pull_request_id,omitempty"`

	// Present in: 8/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk
	Query *string `json:"query,omitempty"`

	// Present in: 7/334 events – public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify
	ReadOnly *string `json:"read_only,omitempty"`

	// Present in: 107/334 events – actions_cache.delete, artifact.destroy, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.restore, codespaces.start_environment, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, migration.create, org.add_outside_collaborator, project.close, project.link, project.rename, project.unlink, protected_branch.update_merge_queue_enforcement_level, public_key.delete, public_key.unverify, public_key.update, public_key.verification_failure, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.archived, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, sponsors.update_tier_repository, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	Repo *string `json:"repo,omitempty"`

	// Present in: 107/334 events – actions_cache.delete, artifact.destroy, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.restore, codespaces.start_environment, copilot.swe_agent_repo_disabled, copilot.swe_agent_repo_enabled, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, migration.create, org.add_outside_collaborator, project.close, project.link, project.rename, project.unlink, protected_branch.update_merge_queue_enforcement_level, public_key.delete, public_key.unverify, public_key.update, public_key.verification_failure, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.archived, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, sponsors.update_tier_repository, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	RepoId *int64 `json:"repo_id,omitempty"`

	// Present in: 1/334 events – repo.transfer
	RepoWas *string `json:"repo_was,omitempty"`

	// Present in: 1/334 events – integration_installation.repositories_added
	RepositoriesAdded []int64 `json:"repositories_added,omitempty"`

	// Present in: 1/334 events – integration_installation.repositories_added
	RepositoriesAddedNames []string `json:"repositories_added_names,omitempty"`

	// Present in: 1/334 events – integration_installation.repositories_removed
	RepositoriesRemoved *string `json:"repositories_removed,omitempty"`

	// Present in: 1/334 events – integration_installation.repositories_removed
	RepositoriesRemovedNames *string `json:"repositories_removed_names,omitempty"`

	// Present in: 6/334 events – codespaces.connect, codespaces.create, codespaces.destroy, repo.advanced_security_disabled, repo.advanced_security_enabled, sponsors.repo_funding_links_file_action
	Repository *string `json:"repository,omitempty"`

	// Present in: 6/334 events – codespaces.connect, codespaces.create, codespaces.destroy, repo.advanced_security_disabled, repo.advanced_security_enabled, sponsors.repo_funding_links_file_action
	RepositoryId *int64 `json:"repository_id,omitempty"`

	// Present in: 14/334 events – integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update
	RepositorySelection *string `json:"repository_selection,omitempty"`

	// Present in: 135/334 events – actions_cache.delete, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.set_actions_private_fork_pr_approvals_policy, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, codespaces.start_environment, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, integration.create, integration.remove_client_secret, integration_installation.suspend, marketplace_agreement_signature.create, migration.create, oauth_access.create, oauth_access.revoke, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_authorization.create, oauth_authorization.update, org.add_outside_collaborator, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_default_workflow_permissions, org.set_workflow_permission_can_approve_pr, pages_protected_domain.create, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.remove, payment_method.update, personal_access_token.credential_regenerated, personal_access_token.destroy, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, repo.advanced_security_disabled, repo.code_scanning_analysis_deleted, repo.create_actions_variable, repo.create_integration_secret, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.register_self_hosted_runner, repo.remove_actions_variable, repo.remove_integration_secret, repo.set_default_workflow_permissions, repo.set_workflow_permission_can_approve_pr, repo.transfer_outgoing, repo.transfer_start, repo.update_actions_variable, repo.update_integration_secret, repository_image.create, repository_image.destroy, repository_invitation.cancel, repository_ruleset.create, repository_ruleset.destroy, security_key.register, security_key.remove, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsored_developer_profile_update, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.remove_factor, user.add_email, user.async_delete, user.block_user, user.change_password, user.create_integration_secret, user.delete, user.demote, user.destroy, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.remove_integration_secret, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_viewed, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, workflows.approve_workflow_job, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	RequestAccessSecurityHeader *string `json:"request_access_security_header,omitempty"`

	// Present in: 2/334 events – repo.create, repo.destroy
	RequestCategory *string `json:"request_category,omitempty"`

	// Present in: 327/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	RequestId *string `json:"request_id,omitempty"`

	// Present in: 2/334 events – repo.create, repo.destroy
	RequestMethod *string `json:"request_method,omitempty"`

	// Present in: 8/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk
	RequestedAt *time.Time `json:"requested_at,omitempty"`

	// Present in: 1/334 events – integration.transfer
	Requester *string `json:"requester,omitempty"`

	// Present in: 1/334 events – integration.transfer
	RequesterId *string `json:"requester_id,omitempty"`

	// Present in personal access token events
	Repositories []int64 `json:"repositories,omitempty"`

	// Present in environment-related events
	EnvironmentId *int64 `json:"environment_id,omitempty"`

	// Present in events with value changes
	OldValue *string `json:"old_value,omitempty"`

	// Present in: 2/334 events – repository_ruleset.create, repository_ruleset.destroy
	RulesetBypassActors *string `json:"ruleset_bypass_actors,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetBypassActorsAdded *string `json:"ruleset_bypass_actors_added,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetBypassActorsDeleted *string `json:"ruleset_bypass_actors_deleted,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetBypassActorsUpdated *string `json:"ruleset_bypass_actors_updated,omitempty"`

	// Present in: 1/334 events – repository_ruleset.create
	RulesetConditions []map[string]interface{} `json:"ruleset_conditions,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetConditionsAdded *string `json:"ruleset_conditions_added,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetConditionsDeleted *string `json:"ruleset_conditions_deleted,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetConditionsUpdated *string `json:"ruleset_conditions_updated,omitempty"`

	// Present in: 3/334 events – repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update
	RulesetEnforcement *string `json:"ruleset_enforcement,omitempty"`

	// Present in: 3/334 events – repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update
	RulesetId *int64 `json:"ruleset_id,omitempty"`

	// Present in: 3/334 events – repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update
	RulesetName *string `json:"ruleset_name,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetOldEnforcement *string `json:"ruleset_old_enforcement,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetOldName *string `json:"ruleset_old_name,omitempty"`

	// Present in: 2/334 events – repository_ruleset.create, repository_ruleset.destroy
	RulesetRules []map[string]interface{} `json:"ruleset_rules,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetRulesAdded *string `json:"ruleset_rules_added,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetRulesDeleted *string `json:"ruleset_rules_deleted,omitempty"`

	// Present in: 1/334 events – repository_ruleset.update
	RulesetRulesUpdated *string `json:"ruleset_rules_updated,omitempty"`

	// Present in: 3/334 events – repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update
	RulesetSourceType *string `json:"ruleset_source_type,omitempty"`

	// Present in: 2/334 events – workflows.approve_workflow_job, workflows.reject_workflow_job
	RunNumber *string `json:"run_number,omitempty"`

	// Present in: 1/334 events – copilot.cfb_seat_cancelled
	SeatAssignment *string `json:"seat_assignment,omitempty"`

	// Present in: 6/334 events – marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject
	SecondaryCategory *string `json:"secondary_category,omitempty"`

	// Present in: 7/334 events – sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.sponsored_developer_disable, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.withdraw_agreement_signature
	SponsorsListingId *string `json:"sponsors_listing_id,omitempty"`

	// Present in: 4/334 events – business.security_center_export_code_scanning_metrics, business.security_center_export_overview_dashboard, org.security_center_export_code_scanning_metrics, org.security_center_export_overview_dashboard
	StartDate *time.Time `json:"start_date,omitempty"`

	// Present in: 1/334 events – workflows.delete_workflow_run
	StartedAt *string `json:"started_at,omitempty"`

	// Present in: 3/334 events – pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify
	State *string `json:"state,omitempty"`

	// Present in: 1/334 events – project.update_team_permission
	Team *string `json:"team,omitempty"`

	// Present in: 9/334 events – git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify
	Title *string `json:"title,omitempty"`

	// Present in: 3/334 events – copilot.cfb_seat_added, copilot.cfb_seat_assignment_refreshed, oauth_access.revoke
	TokenId *int64 `json:"token_id,omitempty"`

	// Present in: 58/334 events – actions_cache.delete, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.suspend_environment, copilot.cfb_seat_assignment_refreshed, environment.create_actions_secret, environment.delete, environment.remove_actions_secret, gist.create, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration_installation.repositories_added, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_authorization.create, oauth_authorization.destroy, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, public_key.create, public_key.delete, public_key.unverification_failure, public_key.verify, repo.actions_enabled, repo.add_member, repo.archived, repo.change_merge_setting, repo.create, repo.create_actions_secret, repo.destroy, repo.remove_actions_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.update_actions_secret, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_invitation.accept, repository_invitation.create, user.creation_rate_limit_exceeded, user.promote, user.remove_email, user.rename, user.suspend, user.unsuspend, user_status.update, workflows.approve_workflow_job
	TokenScopes *string `json:"token_scopes,omitempty"`

	// Present in: 2/334 events – repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted
	Tool *string `json:"tool,omitempty"`

	// Present in: 2/334 events – repo.add_topic, repo.remove_topic
	Topic *string `json:"topic,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferFrom *string `json:"transfer_from,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferFromId *string `json:"transfer_from_id,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferFromType *string `json:"transfer_from_type,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferTo *string `json:"transfer_to,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferToId *string `json:"transfer_to_id,omitempty"`

	// Present in: 1/334 events – integration.transfer
	TransferToType *string `json:"transfer_to_type,omitempty"`

	// Present in: 1/334 events – workflows.delete_workflow_run
	TriggerId *string `json:"trigger_id,omitempty"`

	// Present in: 1/334 events – repo.update_actions_settings
	UpdatedAccessPolicy *string `json:"updated_access_policy,omitempty"`

	// Present in: 200/334 events – account.plan_change, actions_cache.delete, billing.change_billing_type, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, checks.auto_trigger_disabled, checks.auto_trigger_enabled, codespaces.start_environment, copilot.cfb_seat_added, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, integration.create, integration.destroy, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.create, marketplace_listing.redraft, marketplace_listing.reject, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_access.update, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.update_member, passkey.register, passkey.remove, payment_method.create, payment_method.remove, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.credential_revoked, personal_access_token.destroy, personal_access_token.request_created, personal_access_token.update, profile_picture.update, project.access, project.create, project.delete, project.open, project.update_user_permission, project_collaborator.remove, project_collaborator.update, public_key.create, public_key.unverification_failure, public_key.verification_failure, public_key.verify, repo.access, repo.add_member, repo.add_topic, repo.archived, repo.create, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_source, repo.remove_member, repo.remove_topic, repo.rename, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.temporary_access_granted, repo.transfer, repo.transfer_start, repo.unarchived, repo.update_default_branch, repo.update_member, repository_image.create, repository_image.destroy, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.reject_workflow_job
	User *string `json:"user,omitempty"`

	// Present in: 326/334 events – account.plan_change, actions_cache.delete, artifact.destroy, billing.change_billing_type, billing.change_email, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, business.set_actions_fork_pr_approvals_policy, business.set_actions_private_fork_pr_approvals_policy, business.set_actions_retention_limit, business.set_default_workflow_permissions, business.set_fork_pr_workflows_policy, business.set_workflow_permission_can_approve_pr, checks.auto_trigger_disabled, checks.auto_trigger_enabled, checks.delete_logs, codespaces.allow_permissions, codespaces.connect, codespaces.create, codespaces.destroy, codespaces.export_environment, codespaces.restore, codespaces.start_environment, codespaces.suspend_environment, codespaces.trusted_repositories_access_update, copilot.cfb_seat_added, copilot.cfb_seat_assignment_created, copilot.cfb_seat_assignment_refreshed, copilot.cfb_seat_assignment_reused, copilot.cfb_seat_assignment_unassigned, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, copilot.swe_agent_repo_enabled, copilot.swe_agent_repo_enablement_updated, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_repository_access.repositories_updated, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, environment.add_protection_rule, environment.create_actions_secret, environment.create_actions_variable, environment.delete, environment.remove_actions_secret, environment.remove_actions_variable, environment.remove_protection_rule, environment.update_actions_secret, environment.update_actions_variable, environment.update_protection_rule, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, hook.active_changed, hook.config_changed, hook.create, hook.destroy, hook.events_changed, integration.create, integration.destroy, integration.manager_added, integration.manager_removed, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.change_category, marketplace_listing.create, marketplace_listing.delist, marketplace_listing.redraft, marketplace_listing.reject, migration.create, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.update, oauth_application.create, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.add_outside_collaborator, org.advanced_security_disabled_for_new_repos, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_for_new_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.set_actions_fork_pr_approvals_policy, org.set_actions_private_fork_pr_approvals_policy, org.set_actions_retention_limit, org.set_default_workflow_permissions, org.set_fork_pr_workflows_policy, org.set_workflow_permission_can_approve_pr, org.update_member, org.update_member_repository_creation_permission, org.update_member_repository_invitation_permission, pages_protected_domain.create, pages_protected_domain.delete, pages_protected_domain.verify, passkey.register, passkey.remove, payment_method.create, payment_method.update, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update, profile_picture.update, project.access, project.close, project.create, project.delete, project.link, project.open, project.rename, project.unlink, project.update_org_permission, project.update_team_permission, project.update_user_permission, project.visibility_private, project.visibility_public, project_collaborator.add, project_collaborator.remove, project_collaborator.update, project_field.create, project_field.delete, project_view.create, project_view.delete, protected_branch.update_merge_queue_enforcement_level, public_key.create, public_key.delete, public_key.unverification_failure, public_key.unverify, public_key.update, public_key.verification_failure, public_key.verify, repo.access, repo.actions_enabled, repo.add_member, repo.add_topic, repo.advanced_security_disabled, repo.advanced_security_enabled, repo.archived, repo.change_merge_setting, repo.code_scanning_analysis_deleted, repo.code_scanning_configuration_for_branch_deleted, repo.config.disable_collaborators_only, repo.config.disable_contributors_only, repo.config.disable_sockpuppet_disallowed, repo.config.enable_collaborators_only, repo.config.enable_contributors_only, repo.config.enable_sockpuppet_disallowed, repo.create, repo.create_actions_secret, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete_restore, repo.pages_source, repo.register_self_hosted_runner, repo.remove_actions_secret, repo.remove_actions_variable, repo.remove_integration_secret, repo.remove_member, repo.remove_self_hosted_runner, repo.remove_topic, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.staff_unlock, repo.temporary_access_granted, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_secret, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, repository_image.create, repository_image.destroy, repository_invitation.accept, repository_invitation.cancel, repository_invitation.create, repository_invitation.reject, repository_ruleset.create, repository_ruleset.destroy, repository_ruleset.update, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.custom_amount_settings_change, sponsors.fiscal_host_change, sponsors.repo_funding_links_file_action, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_profile_update, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, successor_invitation.accept, successor_invitation.cancel, successor_invitation.create, successor_invitation.decline, successor_invitation.revoke, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.reject_workflow_job, workflows.unpin_workflow
	UserAgent *string `json:"user_agent,omitempty"`

	// Present in: 201/334 events – account.plan_change, actions_cache.delete, billing.change_billing_type, business.security_center_export_code_scanning_metrics, business.security_center_export_coverage, business.security_center_export_overview_dashboard, business.security_center_export_risk, checks.auto_trigger_disabled, checks.auto_trigger_enabled, codespaces.connect, codespaces.start_environment, copilot.cfb_seat_added, copilot.cfb_seat_cancelled, copilot.cfb_seat_cancelled_by_staff, dependabot_alerts.disable, dependabot_alerts.enable, dependabot_alerts_new_repos.disable, dependabot_alerts_new_repos.enable, dependabot_security_updates.disable, dependabot_security_updates.enable, dependabot_security_updates_new_repos.disable, dependabot_security_updates_new_repos.enable, dependency_graph.disable, dependency_graph.enable, dependency_graph_new_repos.disable, dependency_graph_new_repos.enable, gist.create, gist.destroy, gist.visibility_change, git_signing_ssh_public_key.create, git_signing_ssh_public_key.delete, integration.create, integration.destroy, integration.remove_client_secret, integration.revoke_all_tokens, integration.revoke_tokens, integration.suspend, integration.transfer, integration.unsuspend, integration_installation.create, integration_installation.destroy, integration_installation.repositories_added, integration_installation.repositories_removed, integration_installation.suspend, integration_installation.unsuspend, integration_installation.version_updated, marketplace_agreement_signature.create, marketplace_listing.approve, marketplace_listing.create, marketplace_listing.redraft, marketplace_listing.reject, oauth_access.create, oauth_access.destroy, oauth_access.regenerate, oauth_access.revoke, oauth_access.update, oauth_application.destroy, oauth_application.generate_client_secret, oauth_application.remove_client_secret, oauth_application.reset_secret, oauth_application.revoke_all_tokens, oauth_application.revoke_tokens, oauth_application.transfer, oauth_authorization.create, oauth_authorization.destroy, oauth_authorization.update, org.add_member, org.advanced_security_disabled_on_all_repos, org.advanced_security_enabled_on_all_repos, org.remove_member, org.security_center_export_code_scanning_metrics, org.security_center_export_coverage, org.security_center_export_overview_dashboard, org.security_center_export_risk, org.update_member, passkey.register, passkey.remove, payment_method.create, payment_method.remove, personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.credential_revoked, personal_access_token.destroy, personal_access_token.request_created, personal_access_token.update, profile_picture.update, project.access, project.create, project.delete, project.open, project.update_user_permission, project_collaborator.remove, project_collaborator.update, public_key.create, public_key.unverification_failure, public_key.verification_failure, public_key.verify, repo.access, repo.add_member, repo.add_topic, repo.archived, repo.create, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_source, repo.remove_member, repo.remove_topic, repo.rename, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.temporary_access_granted, repo.transfer, repo.transfer_start, repo.unarchived, repo.update_default_branch, repo.update_member, repository_image.create, repository_image.destroy, security_key.register, security_key.remove, sponsors.agreement_sign, sponsors.sponsor_sponsorship_cancel, sponsors.sponsor_sponsorship_create, sponsors.sponsor_sponsorship_payment_complete, sponsors.sponsor_sponsorship_preference_change, sponsors.sponsor_sponsorship_tier_change, sponsors.sponsored_developer_approve, sponsors.sponsored_developer_create, sponsors.sponsored_developer_disable, sponsors.sponsored_developer_redraft, sponsors.sponsored_developer_request_approval, sponsors.sponsored_developer_tier_description_update, sponsors.sponsored_developer_update_newsletter_send, sponsors.sponsors_patreon_user_create, sponsors.sponsors_patreon_user_destroy, sponsors.update_tier_repository, sponsors.update_tier_welcome_message, sponsors.waitlist_join, sponsors.withdraw_agreement_signature, trusted_device.register, trusted_device.remove, two_factor_authentication.add_factor, two_factor_authentication.disabled, two_factor_authentication.enabled, two_factor_authentication.password_reset_fallback_sms, two_factor_authentication.recovery_codes_regenerated, two_factor_authentication.remove_factor, two_factor_authentication.sign_in_fallback_sms, two_factor_authentication.update_fallback, user.add_email, user.async_delete, user.audit_log_export, user.block_user, user.change_password, user.codespaces_trusted_repo_access_granted, user.codespaces_trusted_repo_access_revoked, user.create, user.create_integration_secret, user.creation_rate_limit_exceeded, user.delete, user.demote, user.destroy, user.failed_login, user.forgot_password, user.hide_private_contributions_count, user.login, user.logout, user.new_device_used, user.promote, user.recreate, user.remove_email, user.remove_integration_secret, user.rename, user.reset_password, user.show_private_contributions_count, user.sign_in_from_unrecognized_device, user.sign_in_from_unrecognized_device_and_location, user.suspend, user.two_factor_challenge_failure, user.two_factor_challenge_success, user.two_factor_recover, user.two_factor_recovery_codes_downloaded, user.two_factor_recovery_codes_printed, user.two_factor_recovery_codes_viewed, user.two_factor_requested, user.unblock_user, user.unsuspend, user.update_integration_secret, user_email.confirm_claim, user_status.destroy, user_status.update, workflows.approve_workflow_job, workflows.reject_workflow_job
	UserId *int64 `json:"user_id,omitempty"`

	// Present in: 3/334 events – personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.request_created
	UserProgrammaticAccessId *string `json:"user_programmatic_access_id,omitempty"`

	// Present in: 10/334 events – personal_access_token.access_granted, personal_access_token.access_revoked, personal_access_token.create, personal_access_token.credential_regenerated, personal_access_token.credential_revoked, personal_access_token.destroy, personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied, personal_access_token.update
	UserProgrammaticAccessName *string `json:"user_programmatic_access_name,omitempty"`

	// Present in: 3/334 events – personal_access_token.request_cancelled, personal_access_token.request_created, personal_access_token.request_denied
	UserProgrammaticAccessRequestId *int64 `json:"user_programmatic_access_request_id,omitempty"`

	// Present in: 47/334 events – checks.auto_trigger_disabled, checks.auto_trigger_enabled, environment.create_actions_secret, environment.create_actions_variable, environment.update_actions_secret, environment.update_actions_variable, gist.create, gist.destroy, gist.visibility_change, org.update_member_repository_creation_permission, repo.access, repo.add_member, repo.archived, repo.create, repo.create_actions_variable, repo.create_integration_secret, repo.destroy, repo.pages_cname, repo.pages_create, repo.pages_destroy, repo.pages_https_redirect_disabled, repo.pages_https_redirect_enabled, repo.pages_private, repo.pages_public, repo.pages_soft_delete, repo.pages_soft_delete_restore, repo.pages_source, repo.remove_member, repo.rename, repo.set_actions_fork_pr_approvals_policy, repo.set_actions_private_fork_pr_approvals_policy, repo.set_actions_retention_limit, repo.set_default_workflow_permissions, repo.set_fork_pr_workflows_policy, repo.set_workflow_permission_can_approve_pr, repo.transfer, repo.transfer_outgoing, repo.transfer_start, repo.unarchived, repo.update_actions_access_settings, repo.update_actions_settings, repo.update_actions_variable, repo.update_default_branch, repo.update_integration_secret, repo.update_member, user.create_integration_secret, user.update_integration_secret
	Visibility *string `json:"visibility,omitempty"`

	// Present in: 4/334 events – workflows.disable_workflow, workflows.enable_workflow, workflows.pin_workflow, workflows.unpin_workflow
	WorkflowId *int64 `json:"workflow_id,omitempty"`

	// Present in: 3/334 events – workflows.approve_workflow_job, workflows.delete_workflow_run, workflows.reject_workflow_job
	WorkflowRunId *string `json:"workflow_run_id,omitempty"`
}

// We can have org, and org_id value slice of int64 or int64
// - For oauth_authorization.create, 	user.failed_login we will have slice of int64
// > select distinct org from github_security_log
// +---------------------------------------------------------------+
// | org                                                           |
// +---------------------------------------------------------------+
// | map[name:turbotio names:<nil>]                                |
// | map[name:pro-cloud-49 names:<nil>]                            |
// | map[name:turbot names:<nil>]                                  |
// | map[name:<nil> names:[turbotio turbot pro-cloud-49 do-enter]] |
// | map[name:<nil> names:<nil>]                                   |
// | map[name:<nil> names:[]]                                      |
// +---------------------------------------------------------------+
// > select distinct org_id from github_security_log
// +----------------------------------------------------------+
// | org_id                                                   |
// +----------------------------------------------------------+
// | map[id:98822760 ids:<nil>]                               |
// | map[id:10854165 ids:<nil>]                               |
// | map[id:<nil> ids:<nil>]                                  |
// | map[id:<nil> ids:[]]                                     |
// | map[id:<nil> ids:[10854165 38865304 98822760 193256578]] |
// | map[id:38865304 ids:<nil>]                               |
// +----------------------------------------------------------+
type OrganizationId struct {
	Id  *int64
	Ids []int64
}

type OrganizationName struct {
	Name  *string
	Names []string
}

type RulesetCondition struct {
	ID         int64               `json:"id"`
	Parameters map[string][]string `json:"parameters"`
	Target     string              `json:"target"`
}

func (s *SecurityLog) GetColumnDescriptions() map[string]string {
	return map[string]string{
		"timestamp":                           "The timestamp when the security event occurred.",
		"document_id":                         "Unique identifier for the document in the security log.",
		"action":                              "The type of security action that was performed (e.g., repo.create, org.invite_member).",
		"actions_cache_id":                    "Identifier for the GitHub Actions cache involved in the event.",
		"actions_cache_key":                   "The key of the GitHub Actions cache.",
		"actions_cache_scope":                 "The scope of the GitHub Actions cache (repository, organization, etc.).",
		"actions_cache_version":               "The version of the GitHub Actions cache.",
		"active":                              "Current active status of the entity (true/false).",
		"active_was":                          "Previous active status of the entity before the change.",
		"actor":                               "The username of the user who performed the action.",
		"actor_id":                            "The unique identifier of the user who performed the action.",
		"actor_is_bot":                        "Whether the actor is a bot account (true/false).",
		"application_client_id":               "The client ID of the OAuth application involved in the event.",
		"approvers":                           "List of users who can approve the action or policy.",
		"approvers_was":                       "Previous list of approvers before the change.",
		"blocked_user":                        "The username of the user who was blocked.",
		"branch":                              "The branch name associated with the security event.",
		"business":                            "The business account name associated with the event.",
		"business_id":                         "The unique identifier of the business account.",
		"can_admins_bypass":                   "Whether administrators can bypass the security policy (true/false).",
		"category":                            "The category of the security event or action.",
		"cname":                               "The custom domain name (CNAME) associated with the event.",
		"collaborator":                        "The username of the collaborator involved in the event.",
		"collaborator_type":                   "The type of collaborator (outside, direct, etc.).",
		"content_type":                        "The MIME type of the content involved in the event.",
		"created_at":                          "The timestamp when the resource was created.",
		"devcontainer_path":                   "The path to the development container configuration.",
		"domain":                              "The domain name associated with the security event.",
		"email":                               "The email address associated with the event.",
		"emoji":                               "The emoji associated with the event (for reactions, etc.).",
		"end_date":                            "The end date of a time-based security policy or event.",
		"environment_name":                    "The name of the deployment environment.",
		"events":                              "List of events associated with a webhook or integration.",
		"events_were":                         "Previous list of events before the change.",
		"explanation":                         "Additional explanation or context for the security event.",
		"filename":                            "The name of the file involved in the security event.",
		"fingerprint":                         "The fingerprint of a security key or certificate.",
		"gist_id":                             "The unique identifier of the gist involved in the event.",
		"hashed_token":                        "The hashed version of an authentication token.",
		"head_branch":                         "The head branch of a pull request or merge.",
		"head_sha":                            "The SHA hash of the head commit.",
		"hook_id":                             "The unique identifier of the webhook.",
		"integration":                         "The name or identifier of the integration involved.",
		"invitee":                             "The username of the user who was invited.",
		"inviter":                             "The username of the user who sent the invitation.",
		"key":                                 "The SSH key or API key involved in the event.",
		"limit":                               "The rate limit or quota limit associated with the event.",
		"limited_availability":                "Whether the feature has limited availability (true/false).",
		"machine_type":                        "The type of machine used for GitHub Actions runners.",
		"manager":                             "The username of the user who manages the resource.",
		"marketplace_listing":                 "The GitHub Marketplace listing associated with the event.",
		"merge_queue_enforcement_level":       "The enforcement level of the merge queue policy.",
		"message":                             "The message or description associated with the event.",
		"name":                                "The name of the resource or entity involved in the event.",
		"new_access":                          "The new access level granted in the permission change.",
		"new_nwo":                             "The new name/owner combination for a repository transfer.",
		"new_policy":                          "The new security policy that was applied.",
		"new_repo_base_role":                  "The new base role for repository access.",
		"new_repo_permission":                 "The new repository permission level.",
		"new_value":                           "The new value after a configuration change.",
		"nickname":                            "The nickname or display name associated with the user.",
		"oauth_application":                   "The OAuth application involved in the authorization event.",
		"oauth_application_id":                "The unique identifier of the OAuth application.",
		"oauth_application_name":              "The name of the OAuth application.",
		"old_access":                          "The previous access level before the permission change.",
		"old_base_role":                       "The previous base role before the change.",
		"old_cname":                           "The previous custom domain name before the change.",
		"old_login":                           "The previous username before the account change.",
		"old_name":                            "The previous name of the resource before the change.",
		"old_permission":                      "The previous permission level before the change.",
		"old_policy":                          "The previous security policy before the change.",
		"old_project_role":                    "The previous project role before the change.",
		"old_repo_base_role":                  "The previous repository base role before the change.",
		"old_repo_permission":                 "The previous repository permission before the change.",
		"old_user":                            "The previous user before a transfer or change.",
		"operation_type":                      "The type of operation performed (create, update, delete, etc.).",
		"org":                                 "The organization name where the security event occurred.",
		"org_id":                              "The unique identifier of the organization.",
		"origin_repository":                   "The original repository in a fork or transfer operation.",
		"owner":                               "The owner of the repository or resource.",
		"owner_type":                          "The type of owner (User, Organization, etc.).",
		"passkey_nickname":                    "The nickname assigned to a passkey for identification.",
		"patreon_email":                       "The Patreon email address associated with sponsorship.",
		"patreon_username":                    "The Patreon username associated with sponsorship.",
		"permissions":                         "The permissions associated with the security event.",
		"permissions_added":                   "Permissions that were added in the change.",
		"permissions_unchanged":               "Permissions that remained unchanged.",
		"permissions_upgraded":                "Permissions that were upgraded or enhanced.",
		"policy":                              "The security policy applied to the resource.",
		"prevent_self_review":                 "Whether self-review is prevented in pull requests (true/false).",
		"previous_visibility":                 "The previous visibility setting before the change (public, private, internal).",
		"primary_category":                    "The primary category classification of the event.",
		"programmatic_access_type":            "The type of programmatic access (token, key, etc.).",
		"project_id":                          "The unique identifier of the project.",
		"project_kind":                        "The type or kind of project (classic, next-gen, etc.).",
		"project_name":                        "The name of the project involved in the event.",
		"project_role":                        "The role assigned within the project.",
		"public_project":                      "Whether the project is publicly visible (true/false).",
		"public_repo":                         "Whether the repository is publicly visible (true/false).",
		"pull_request_id":                     "The unique identifier of the pull request.",
		"query":                               "The search query or filter used in the event.",
		"read_only":                           "Whether the access is read-only (true/false).",
		"repo":                                "The repository name where the security event occurred.",
		"repo_id":                             "The unique identifier of the repository.",
		"repo_was":                            "The previous repository before a transfer or change.",
		"repositories_added":                  "List of repositories that were added to a scope or permission.",
		"repositories_added_names":            "Names of repositories that were added.",
		"repositories_removed":                "List of repositories that were removed from a scope or permission.",
		"repositories_removed_names":          "Names of repositories that were removed.",
		"repository":                          "The full name of the repository (owner/repo).",
		"repository_id":                       "The unique identifier of the repository.",
		"repository_selection":                "The repository selection criteria (all, selected, etc.).",
		"request_access_security_header":      "Security headers included in the access request.",
		"request_category":                    "The category of the access request.",
		"request_id":                          "The unique identifier of the request.",
		"request_method":                      "The HTTP method used in the request (GET, POST, etc.).",
		"requested_at":                        "The timestamp when the request was made.",
		"requester":                           "The username of the user who made the request.",
		"requester_id":                        "The unique identifier of the user who made the request.",
		"repositories":                        "Array of repository IDs associated with the security event.",
		"environment_id":                      "The unique identifier of the environment involved in the event.",
		"old_value":                           "The previous value before a configuration change.",
		"ruleset_bypass_actors":               "List of actors who can bypass the ruleset.",
		"ruleset_bypass_actors_added":         "Bypass actors that were added to the ruleset.",
		"ruleset_bypass_actors_deleted":       "Bypass actors that were removed from the ruleset.",
		"ruleset_bypass_actors_updated":       "Bypass actors that were updated in the ruleset.",
		"ruleset_conditions":                  "Conditions defined in the ruleset.",
		"ruleset_conditions_added":            "Conditions that were added to the ruleset.",
		"ruleset_conditions_deleted":          "Conditions that were removed from the ruleset.",
		"ruleset_conditions_updated":          "Conditions that were updated in the ruleset.",
		"ruleset_enforcement":                 "The enforcement level of the ruleset (active, evaluate, disabled).",
		"ruleset_id":                          "The unique identifier of the ruleset.",
		"ruleset_name":                        "The name of the ruleset.",
		"ruleset_old_enforcement":             "The previous enforcement level before the change.",
		"ruleset_old_name":                    "The previous name of the ruleset before the change.",
		"ruleset_rules":                       "The rules defined in the ruleset.",
		"ruleset_rules_added":                 "Rules that were added to the ruleset.",
		"ruleset_rules_deleted":               "Rules that were removed from the ruleset.",
		"ruleset_rules_updated":               "Rules that were updated in the ruleset.",
		"ruleset_source_type":                 "The source type of the ruleset (repository, organization).",
		"run_number":                          "The run number of the GitHub Actions workflow.",
		"seat_assignment":                     "The seat assignment information for licensed users.",
		"secondary_category":                  "The secondary category classification of the event.",
		"sponsors_listing_id":                 "The unique identifier of the sponsors listing.",
		"start_date":                          "The start date of a time-based security policy or event.",
		"started_at":                          "The timestamp when the process or workflow started.",
		"state":                               "The current state of the resource (active, inactive, pending, etc.).",
		"team":                                "The team name involved in the security event.",
		"title":                               "The title or name of the resource or event.",
		"token_id":                            "The unique identifier of the authentication token.",
		"token_scopes":                        "The scopes or permissions granted to the token.",
		"tool":                                "The tool or service that triggered the security event.",
		"topic":                               "The topic or subject associated with the event.",
		"transfer_from":                       "The source account in a transfer operation.",
		"transfer_from_id":                    "The unique identifier of the source account in a transfer.",
		"transfer_from_type":                  "The type of the source account in a transfer (User, Organization).",
		"transfer_to":                         "The destination account in a transfer operation.",
		"transfer_to_id":                      "The unique identifier of the destination account in a transfer.",
		"transfer_to_type":                    "The type of the destination account in a transfer (User, Organization).",
		"trigger_id":                          "The unique identifier of the trigger that caused the event.",
		"updated_access_policy":               "The updated access policy after the change.",
		"user":                                "The username of the user involved in the security event.",
		"user_agent":                          "The user agent string from the client that made the request.",
		"user_id":                             "The unique identifier of the user involved in the event.",
		"user_programmatic_access_id":         "The unique identifier of the user's programmatic access credential.",
		"user_programmatic_access_name":       "The name of the user's programmatic access credential.",
		"user_programmatic_access_request_id": "The unique identifier of the programmatic access request.",
		"visibility":                          "The visibility setting of the resource (public, private, internal).",
		"workflow_id":                         "The unique identifier of the GitHub Actions workflow.",
		"workflow_run_id":                     "The unique identifier of the GitHub Actions workflow run.",
		"tp_index":                            "The organization name or 'default' if not set.",
		"tp_ips":                              "IP addresses related to the event.",
		"tp_source_ip":                        "The IP address of the actor.",
	}
}

func (a *SecurityLog) mapSecurityLogFields(in map[string]interface{}) {
	// Create a map to hold dynamic fields
	dynamicFields := make(map[string]interface{})

	for key, value := range in {
		switch key {
		case "@timestamp":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.Timestamp = &t
			}
		case "_document_id":
			if strVal, ok := value.(string); ok {
				a.DocumentId = &strVal
			}
		case "action":
			if strVal, ok := value.(string); ok {
				a.Action = &strVal
			}
		case "actions_cache_id":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheId = &strVal
			}
		case "actions_cache_key":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheKey = &strVal
			}
		case "actions_cache_scope":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheScope = &strVal
			}
		case "actions_cache_version":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheVersion = &strVal
			}
		case "active":
			if strVal, ok := value.(string); ok {
				a.Active = &strVal
			}
		case "active_was":
			if strVal, ok := value.(string); ok {
				a.ActiveWas = &strVal
			}
		case "actor":
			if strVal, ok := value.(string); ok {
				a.Actor = &strVal
			}
		case "actor_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.ActorId = &intVal
			}
		case "actor_is_bot":
			if boolValue, ok := value.(bool); ok {
				a.ActorIsBot = &boolValue
			}
		case "application_client_id":
			if strVal, ok := value.(string); ok {
				a.ApplicationClientId = &strVal
			}
		case "approvers":
			if strVal, ok := value.(string); ok {
				a.Approvers = &strVal
			}
		case "approvers_was":
			if strVal, ok := value.(string); ok {
				a.ApproversWas = &strVal
			}
		case "blocked_user":
			if strVal, ok := value.(string); ok {
				a.BlockedUser = &strVal
			}
		case "branch":
			if strVal, ok := value.(string); ok {
				a.Branch = &strVal
			}
		case "business":
			if strVal, ok := value.(string); ok {
				a.Business = &strVal
			}
		case "business_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.BusinessId = &intVal
			}
		case "can_admins_bypass":
			if strVal, ok := value.(string); ok {
				a.CanAdminsBypass = &strVal
			}
		case "category":
			if strVal, ok := value.(string); ok {
				a.Category = &strVal
			}
		case "cname":
			if strVal, ok := value.(string); ok {
				a.Cname = &strVal
			}
		case "collaborator":
			if strVal, ok := value.(string); ok {
				a.Collaborator = &strVal
			}
		case "collaborator_type":
			if strVal, ok := value.(string); ok {
				a.CollaboratorType = &strVal
			}
		case "content_type":
			if strVal, ok := value.(string); ok {
				a.ContentType = &strVal
			}
		case "created_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.CreatedAt = &t
			}
		case "devcontainer_path":
			if strVal, ok := value.(string); ok {
				a.DevcontainerPath = &strVal
			}
		case "domain":
			if strVal, ok := value.(string); ok {
				a.Domain = &strVal
			}
		case "email":
			if strVal, ok := value.(string); ok {
				a.Email = &strVal
			}
		case "emoji":
			if strVal, ok := value.(string); ok {
				a.Emoji = &strVal
			}
		case "end_date":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.EndDate = &t
			}
		case "environment_name":
			if strVal, ok := value.(string); ok {
				a.EnvironmentName = &strVal
			}
		case "events":
			strArray, err := convertToStringArray(value)
			if err == nil {
				a.Events = strArray
			}
		case "events_were":
			if strVal, ok := value.(string); ok {
				a.EventsWere = &strVal
			}
		case "explanation":
			if strVal, ok := value.(string); ok {
				a.Explanation = &strVal
			}
		case "filename":
			if strVal, ok := value.(string); ok {
				a.Filename = &strVal
			}
		case "fingerprint":
			if strVal, ok := value.(string); ok {
				a.Fingerprint = &strVal
			}
		case "gist_id":
			if strVal, ok := value.(string); ok {
				a.GistId = &strVal
			}
		case "hashed_token":
			if strVal, ok := value.(string); ok {
				a.HashedToken = &strVal
			}
		case "head_branch":
			if strVal, ok := value.(string); ok {
				a.HeadBranch = &strVal
			}
		case "head_sha":
			if strVal, ok := value.(string); ok {
				a.HeadSha = &strVal
			}
		case "hook_id":
			if strVal, ok := value.(string); ok {
				a.HookId = &strVal
			}
		case "integration":
			if strVal, ok := value.(string); ok {
				a.Integration = &strVal
			}
		case "invitee":
			if strVal, ok := value.(string); ok {
				a.Invitee = &strVal
			}
		case "inviter":
			if strVal, ok := value.(string); ok {
				a.Inviter = &strVal
			}
		case "key":
			if strVal, ok := value.(string); ok {
				a.Key = &strVal
			}
		case "limit":
			if strVal, ok := value.(string); ok {
				a.Limit = &strVal
			}
		case "limited_availability":
			if strVal, ok := value.(string); ok {
				a.LimitedAvailability = &strVal
			}
		case "machine_type":
			if strVal, ok := value.(string); ok {
				a.MachineType = &strVal
			}
		case "manager":
			if strVal, ok := value.(string); ok {
				a.Manager = &strVal
			}
		case "marketplace_listing":
			if strVal, ok := value.(string); ok {
				a.MarketplaceListing = &strVal
			}
		case "merge_queue_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.MergeQueueEnforcementLevel = &strVal
			}
		case "message":
			if strVal, ok := value.(string); ok {
				a.Message = &strVal
			}
		case "name":
			if strVal, ok := value.(string); ok {
				a.Name = &strVal
			}
		case "new_access":
			if strVal, ok := value.(string); ok {
				a.NewAccess = &strVal
			}
		case "new_nwo":
			if strVal, ok := value.(string); ok {
				a.NewNwo = &strVal
			}
		case "new_policy":
			if strVal, ok := value.(string); ok {
				a.NewPolicy = &strVal
			}
		case "new_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.NewRepoBaseRole = &strVal
			}
		case "new_repo_permission":
			if strVal, ok := value.(string); ok {
				a.NewRepoPermission = &strVal
			}
		case "new_value":
			if strVal, ok := value.(string); ok {
				a.NewValue = &strVal
			}
		case "nickname":
			if strVal, ok := value.(string); ok {
				a.Nickname = &strVal
			}
		case "oauth_application":
			if strVal, ok := value.(string); ok {
				a.OauthApplication = &strVal
			}
		case "oauth_application_id":
			if strVal, ok := value.(string); ok {
				a.OauthApplicationId = &strVal
			}
		case "oauth_application_name":
			if strVal, ok := value.(string); ok {
				a.OauthApplicationName = &strVal
			}
		case "old_access":
			if strVal, ok := value.(string); ok {
				a.OldAccess = &strVal
			}
		case "old_base_role":
			if strVal, ok := value.(string); ok {
				a.OldBaseRole = &strVal
			}
		case "old_cname":
			if strVal, ok := value.(string); ok {
				a.OldCname = &strVal
			}
		case "old_login":
			if strVal, ok := value.(string); ok {
				a.OldLogin = &strVal
			}
		case "old_name":
			if strVal, ok := value.(string); ok {
				a.OldName = &strVal
			}
		case "old_permission":
			if strVal, ok := value.(string); ok {
				a.OldPermission = &strVal
			}
		case "old_policy":
			if strVal, ok := value.(string); ok {
				a.OldPolicy = &strVal
			}
		case "old_project_role":
			if strVal, ok := value.(string); ok {
				a.OldProjectRole = &strVal
			}
		case "old_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.OldRepoBaseRole = &strVal
			}
		case "old_repo_permission":
			if strVal, ok := value.(string); ok {
				a.OldRepoPermission = &strVal
			}
		case "old_user":
			if strVal, ok := value.(string); ok {
				a.OldUser = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				a.OperationType = &strVal
			}
		case "org":
			if strVal, ok := value.(string); ok {
				a.Org.Name = &strVal
			}
			stringArr, err := convertToStringArray(value)
			if err == nil {
				a.Org.Names = stringArr
			}
		case "org_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.OrgId.Id = &intVal
			}
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.OrgId.Ids = intArr
			}
		case "origin_repository":
			if strVal, ok := value.(string); ok {
				a.OriginRepository = &strVal
			}
		case "owner":
			if strVal, ok := value.(string); ok {
				a.Owner = &strVal
			}
		case "owner_type":
			if strVal, ok := value.(string); ok {
				a.OwnerType = &strVal
			}
		case "passkey_nickname":
			if strVal, ok := value.(string); ok {
				a.PasskeyNickname = &strVal
			}
		case "patreon_email":
			if strVal, ok := value.(string); ok {
				a.PatreonEmail = &strVal
			}
		case "patreon_username":
			if strVal, ok := value.(string); ok {
				a.PatreonUsername = &strVal
			}
		case "permissions":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.Permissions = mapVal
			}

		case "permissions_added":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsAdded = mapVal
			}
		case "permissions_unchanged":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsUnchanged = mapVal
			}
		case "permissions_upgraded":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsUpgraded = mapVal
			}
		case "policy":
			if strVal, ok := value.(string); ok {
				a.Policy = &strVal
			}
		case "prevent_self_review":
			if strVal, ok := value.(string); ok {
				a.PreventSelfReview = &strVal
			}
		case "previous_visibility":
			if strVal, ok := value.(string); ok {
				a.PreviousVisibility = &strVal
			}
		case "primary_category":
			if strVal, ok := value.(string); ok {
				a.PrimaryCategory = &strVal
			}
		case "programmatic_access_type":
			if strVal, ok := value.(string); ok {
				a.ProgrammaticAccessType = &strVal
			}
		case "project_id":
			if strVal, ok := value.(string); ok {
				a.ProjectId = &strVal
			}
		case "project_kind":
			if strVal, ok := value.(string); ok {
				a.ProjectKind = &strVal
			}
		case "project_name":
			if strVal, ok := value.(string); ok {
				a.ProjectName = &strVal
			}
		case "project_role":
			if strVal, ok := value.(string); ok {
				a.ProjectRole = &strVal
			}
		case "public_project":
			if strVal, ok := value.(string); ok {
				a.PublicProject = &strVal
			}
		case "public_repo":
			if strVal, ok := value.(string); ok {
				a.PublicRepo = &strVal
			}
		case "pull_request_id":
			if strVal, ok := value.(string); ok {
				a.PullRequestId = &strVal
			}
		case "query":
			if strVal, ok := value.(string); ok {
				a.Query = &strVal
			}
		case "read_only":
			if strVal, ok := value.(string); ok {
				a.ReadOnly = &strVal
			}
		case "repo":
			if strVal, ok := value.(string); ok {
				a.Repo = &strVal
			}
		case "repo_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RepoId = &intVal
			}
		case "repo_was":
			if strVal, ok := value.(string); ok {
				a.RepoWas = &strVal
			}
		case "repositories_added":
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.RepositoriesAdded = intArr
			}
		case "repositories_added_names":
			stringSliceVal, err := convertToStringArray(value)
			if err == nil {
				a.RepositoriesAddedNames = stringSliceVal
			}
		case "repositories_removed":
			if strVal, ok := value.(string); ok {
				a.RepositoriesRemoved = &strVal
			}
		case "repositories_removed_names":
			if strVal, ok := value.(string); ok {
				a.RepositoriesRemovedNames = &strVal
			}
		case "repository":
			if strVal, ok := value.(string); ok {
				a.Repository = &strVal
			}
		case "repository_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RepositoryId = &intVal
			}
		case "repository_selection":
			if strVal, ok := value.(string); ok {
				a.RepositorySelection = &strVal
			}
		case "request_access_security_header":
			if strVal, ok := value.(string); ok {
				a.RequestAccessSecurityHeader = &strVal
			}
		case "request_category":
			if strVal, ok := value.(string); ok {
				a.RequestCategory = &strVal
			}
		case "request_id":
			if strVal, ok := value.(string); ok {
				a.RequestId = &strVal
			}
		case "request_method":
			if strVal, ok := value.(string); ok {
				a.RequestMethod = &strVal
			}
		case "requested_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.RequestedAt = &t
			}
		case "requester":
			if strVal, ok := value.(string); ok {
				a.Requester = &strVal
			}
		case "requester_id":
			if strVal, ok := value.(string); ok {
				a.RequesterId = &strVal
			}
		case "repositories":
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.Repositories = intArr
			}
		case "environment_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.EnvironmentId = &intVal
			}
		case "old_value":
			if strVal, ok := value.(string); ok {
				a.OldValue = &strVal
			}
		case "ruleset_bypass_actors":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActors = &strVal
			}
		case "ruleset_bypass_actors_added":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsAdded = &strVal
			}
		case "ruleset_bypass_actors_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsDeleted = &strVal
			}
		case "ruleset_bypass_actors_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsUpdated = &strVal
			}
		case "ruleset_conditions":
			val, err := convertToSliceOfMap(value)
			if err == nil {
				a.RulesetConditions = val
			}
		case "ruleset_conditions_added":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsAdded = &strVal
			}
		case "ruleset_conditions_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsDeleted = &strVal
			}
		case "ruleset_conditions_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsUpdated = &strVal
			}
		case "ruleset_enforcement":
			if strVal, ok := value.(string); ok {
				a.RulesetEnforcement = &strVal
			}
		case "ruleset_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RulesetId = &intVal
			}
		case "ruleset_name":
			if strVal, ok := value.(string); ok {
				a.RulesetName = &strVal
			}
		case "ruleset_old_enforcement":
			if strVal, ok := value.(string); ok {
				a.RulesetOldEnforcement = &strVal
			}
		case "ruleset_old_name":
			if strVal, ok := value.(string); ok {
				a.RulesetOldName = &strVal
			}
		case "ruleset_rules":
			val, err := convertToSliceOfMap(value)
			if err == nil {
				a.RulesetRules = val
			}
		case "ruleset_rules_added":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesAdded = &strVal
			}
		case "ruleset_rules_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesDeleted = &strVal
			}
		case "ruleset_rules_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesUpdated = &strVal
			}
		case "ruleset_source_type":
			if strVal, ok := value.(string); ok {
				a.RulesetSourceType = &strVal
			}
		case "run_number":
			if strVal, ok := value.(string); ok {
				a.RunNumber = &strVal
			}
		case "seat_assignment":
			if strVal, ok := value.(string); ok {
				a.SeatAssignment = &strVal
			}
		case "secondary_category":
			if strVal, ok := value.(string); ok {
				a.SecondaryCategory = &strVal
			}
		case "sponsors_listing_id":
			if strVal, ok := value.(string); ok {
				a.SponsorsListingId = &strVal
			}
		case "start_date":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.StartDate = &t
			}
		case "started_at":
			if strVal, ok := value.(string); ok {
				a.StartedAt = &strVal
			}
		case "state":
			if strVal, ok := value.(string); ok {
				a.State = &strVal
			}
		case "team":
			if strVal, ok := value.(string); ok {
				a.Team = &strVal
			}
		case "title":
			if strVal, ok := value.(string); ok {
				a.Title = &strVal
			}
		case "token_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.TokenId = &intVal
			}
		case "token_scopes":
			if strVal, ok := value.(string); ok {
				a.TokenScopes = &strVal
			}
		case "tool":
			if strVal, ok := value.(string); ok {
				a.Tool = &strVal
			}
		case "topic":
			if strVal, ok := value.(string); ok {
				a.Topic = &strVal
			}
		case "transfer_from":
			if strVal, ok := value.(string); ok {
				a.TransferFrom = &strVal
			}
		case "transfer_from_id":
			if strVal, ok := value.(string); ok {
				a.TransferFromId = &strVal
			}
		case "transfer_from_type":
			if strVal, ok := value.(string); ok {
				a.TransferFromType = &strVal
			}
		case "transfer_to":
			if strVal, ok := value.(string); ok {
				a.TransferTo = &strVal
			}
		case "transfer_to_id":
			if strVal, ok := value.(string); ok {
				a.TransferToId = &strVal
			}
		case "transfer_to_type":
			if strVal, ok := value.(string); ok {
				a.TransferToType = &strVal
			}
		case "trigger_id":
			if strVal, ok := value.(string); ok {
				a.TriggerId = &strVal
			}
		case "updated_access_policy":
			if strVal, ok := value.(string); ok {
				a.UpdatedAccessPolicy = &strVal
			}
		case "user":
			if strVal, ok := value.(string); ok {
				a.User = &strVal
			}
		case "user_agent":
			if strVal, ok := value.(string); ok {
				a.UserAgent = &strVal
			}
		case "user_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.UserId = &intVal
			}
		case "user_programmatic_access_id":
			if strVal, ok := value.(string); ok {
				a.UserProgrammaticAccessId = &strVal
			}
		case "user_programmatic_access_name":
			if strVal, ok := value.(string); ok {
				a.UserProgrammaticAccessName = &strVal
			}
		case "user_programmatic_access_request_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.UserProgrammaticAccessRequestId = &intVal
			}
		case "visibility":
			if strVal, ok := value.(string); ok {
				a.Visibility = &strVal
			}
		case "workflow_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.WorkflowId = &intVal
			}
		case "workflow_run_id":
			if strVal, ok := value.(string); ok {
				a.WorkflowRunId = &strVal
			}
		default:
			// Add unknown fields to dynamicFields
			dynamicFields[key] = value
		}
	}
}

// Helper functions

func convertToSliceOfMap(data interface{}) ([]map[string]interface{}, error) {
	rawSlice, ok := data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("data is not a slice")
	}

	result := make([]map[string]interface{}, 0, len(rawSlice))
	for i, item := range rawSlice {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("item at index %d is not a map[string]interface{}", i)
		}
		if idVal, ok := m["id"].(float64); ok {
			id := int64(idVal) // This safely converts 8.560519e+06 to 8560519
			m["id"] = id
		}
		result = append(result, m)
	}

	return result, nil
}

func convertToMapStringString(val interface{}) (map[string]string, error) {
	rawMap, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("input is not a map[string]interface{}")
	}

	result := make(map[string]string)
	for k, v := range rawMap {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("value for key '%s' is not a string (type: %T)", k, v)
		}
		result[k] = str
	}

	return result, nil
}

func toInt64(val interface{}) (int64, error) {
	if val == nil {
		return 0, nil
	}
	switch v := val.(type) {
	case float64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case string:
		// optional: convert string to int64 if needed
		return 0, fmt.Errorf("cannot convert string to int64 directly: %s", v)
	default:
		return 0, fmt.Errorf("unsupported type: %T", val)
	}
}

func convertToStringArray(val interface{}) ([]string, error) {
	rawSlice, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("value is not a slice")
	}

	result := make([]string, 0, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a string (type: %T)", i, v)
		}
		result = append(result, str)
	}

	return result, nil
}

func convertToInt64Slice(val interface{}) ([]int64, error) {
	rawSlice, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("value is not a slice")
	}

	result := make([]int64, 0, len(rawSlice))
	for i, v := range rawSlice {
		num, ok := v.(float64) // JSON numbers are float64 by default
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a float64 (type: %T)", i, v)
		}
		result = append(result, int64(num))
	}

	return result, nil
}
