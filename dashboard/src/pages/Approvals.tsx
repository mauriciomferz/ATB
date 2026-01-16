import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { fetchPendingApprovals, approveRequest, rejectRequest } from '../api';
import type { ApprovalRequest } from '../types';

export default function Approvals() {
  const queryClient = useQueryClient();
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [rejectReason, setRejectReason] = useState('');

  const { data: pendingApprovals, isLoading } = useQuery({
    queryKey: ['approvals', 'pending'],
    queryFn: fetchPendingApprovals,
    refetchInterval: 10000, // Poll every 10 seconds
  });

  const approveMutation = useMutation({
    mutationFn: (requestId: string) => approveRequest(requestId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelectedRequest(null);
    },
  });

  const rejectMutation = useMutation({
    mutationFn: ({ requestId, reason }: { requestId: string; reason: string }) =>
      rejectRequest(requestId, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['approvals'] });
      setSelectedRequest(null);
      setRejectReason('');
    },
  });

  const getRiskBadgeClass = (tier: string) => {
    switch (tier) {
      case 'HIGH':
        return 'bg-danger-100 text-danger-800 dark:bg-danger-900 dark:text-danger-200';
      case 'MEDIUM':
        return 'bg-warning-100 text-warning-800 dark:bg-warning-900 dark:text-warning-200';
      default:
        return 'bg-success-100 text-success-800 dark:bg-success-900 dark:text-success-200';
    }
  };

  const formatTimeRemaining = (expiresAt: string) => {
    const remaining = new Date(expiresAt).getTime() - Date.now();
    if (remaining < 0) return 'Expired';
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Pending Approvals</h1>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-gray-400">
            {pendingApprovals?.length || 0} pending
          </span>
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-warning-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-warning-500"></span>
          </span>
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading...</div>
      ) : pendingApprovals?.length === 0 ? (
        <div className="card text-center py-12">
          <div className="text-4xl mb-4">✓</div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">No pending approvals</h3>
          <p className="text-gray-500 dark:text-gray-400 mt-2">
            All high-risk action requests have been processed.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {pendingApprovals?.map((request) => (
            <div
              key={request.id}
              className={`card cursor-pointer transition-all ${
                selectedRequest?.id === request.id
                  ? 'ring-2 ring-primary-500'
                  : 'hover:shadow-lg'
              }`}
              onClick={() => setSelectedRequest(request)}
            >
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskBadgeClass(
                        request.riskTier
                      )}`}
                    >
                      {request.riskTier}
                    </span>
                    <h3 className="text-lg font-mono font-medium text-gray-900 dark:text-white">
                      {request.action}
                    </h3>
                  </div>
                  <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                    <p>
                      Agent: <span className="font-mono">{request.agentSpiffeId}</span>
                    </p>
                    <p>
                      Requested by: <span className="font-medium">{request.requestedBy}</span>
                    </p>
                    {request.dualControlRequired && (
                      <p className="text-warning-600 dark:text-warning-400">
                        ⚠ Dual control required ({request.approvalCount}/{request.requiredApprovals} approvals)
                      </p>
                    )}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-medium text-gray-900 dark:text-white">
                    Expires in
                  </div>
                  <div className={`text-lg font-mono ${
                    new Date(request.expiresAt).getTime() - Date.now() < 60000
                      ? 'text-danger-600 dark:text-danger-400'
                      : 'text-gray-600 dark:text-gray-400'
                  }`}>
                    {formatTimeRemaining(request.expiresAt)}
                  </div>
                </div>
              </div>

              {/* Constraints Summary */}
              {request.constraints && Object.keys(request.constraints).length > 0 && (
                <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Constraints
                  </h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(request.constraints).map(([key, value]) => (
                      <span
                        key={key}
                        className="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono"
                      >
                        {key}: {String(value)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Approval Modal */}
      {selectedRequest && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                  Review Approval Request
                </h2>
                <button
                  onClick={() => setSelectedRequest(null)}
                  className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-4">
                {/* Risk Warning */}
                {selectedRequest.riskTier === 'HIGH' && (
                  <div className="bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-danger-800 dark:text-danger-200">
                      <span className="text-xl">⚠</span>
                      <span className="font-medium">High-Risk Action</span>
                    </div>
                    <p className="mt-2 text-sm text-danger-700 dark:text-danger-300">
                      This action has been classified as high-risk. Please review all details
                      carefully before approving.
                    </p>
                  </div>
                )}

                {/* Action Details */}
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                  <h3 className="font-medium text-gray-900 dark:text-white mb-3">Action Details</h3>
                  <dl className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Action</dt>
                      <dd className="font-mono text-gray-900 dark:text-white">{selectedRequest.action}</dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Risk Tier</dt>
                      <dd>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getRiskBadgeClass(selectedRequest.riskTier)}`}>
                          {selectedRequest.riskTier}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Agent</dt>
                      <dd className="font-mono text-gray-900 dark:text-white text-xs">{selectedRequest.agentSpiffeId}</dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Requested By</dt>
                      <dd className="text-gray-900 dark:text-white">{selectedRequest.requestedBy}</dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Requested At</dt>
                      <dd className="text-gray-900 dark:text-white">{new Date(selectedRequest.requestedAt).toLocaleString()}</dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 dark:text-gray-400">Expires At</dt>
                      <dd className="text-gray-900 dark:text-white">{new Date(selectedRequest.expiresAt).toLocaleString()}</dd>
                    </div>
                  </dl>
                </div>

                {/* Constraints */}
                {selectedRequest.constraints && Object.keys(selectedRequest.constraints).length > 0 && (
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <h3 className="font-medium text-gray-900 dark:text-white mb-3">Constraints</h3>
                    <pre className="text-xs font-mono bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto">
                      {JSON.stringify(selectedRequest.constraints, null, 2)}
                    </pre>
                  </div>
                )}

                {/* Legal Basis */}
                {selectedRequest.legalBasis && (
                  <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                    <h3 className="font-medium text-gray-900 dark:text-white mb-3">Legal Basis</h3>
                    <dl className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <dt className="text-gray-500 dark:text-gray-400">Basis</dt>
                        <dd className="text-gray-900 dark:text-white">{selectedRequest.legalBasis.basis}</dd>
                      </div>
                      <div>
                        <dt className="text-gray-500 dark:text-gray-400">Jurisdiction</dt>
                        <dd className="text-gray-900 dark:text-white">{selectedRequest.legalBasis.jurisdiction}</dd>
                      </div>
                      <div className="col-span-2">
                        <dt className="text-gray-500 dark:text-gray-400">Accountable Party</dt>
                        <dd className="text-gray-900 dark:text-white">
                          {selectedRequest.legalBasis.accountableParty.id} ({selectedRequest.legalBasis.accountableParty.type})
                        </dd>
                      </div>
                    </dl>
                  </div>
                )}

                {/* Rejection Reason */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Rejection Reason (optional)
                  </label>
                  <textarea
                    value={rejectReason}
                    onChange={(e) => setRejectReason(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    rows={3}
                    placeholder="Enter reason for rejection..."
                  />
                </div>

                {/* Action Buttons */}
                <div className="flex justify-end gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={() => setSelectedRequest(null)}
                    className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => rejectMutation.mutate({ requestId: selectedRequest.id, reason: rejectReason })}
                    disabled={rejectMutation.isPending}
                    className="px-4 py-2 bg-danger-600 text-white rounded-lg hover:bg-danger-700 disabled:opacity-50"
                  >
                    {rejectMutation.isPending ? 'Rejecting...' : 'Reject'}
                  </button>
                  <button
                    onClick={() => approveMutation.mutate(selectedRequest.id)}
                    disabled={approveMutation.isPending}
                    className="px-4 py-2 bg-success-600 text-white rounded-lg hover:bg-success-700 disabled:opacity-50"
                  >
                    {approveMutation.isPending ? 'Approving...' : 'Approve'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
