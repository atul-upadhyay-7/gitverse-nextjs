"use client";

import { useState } from "react";
import { Server, Activity } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { EmptyState } from "@/components/ui/EmptyState";
import { Card, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";

interface WorkerData {
  id: string;
  status: string;
}

export default function Workers() {
  // Simulate an empty worker list
  const [workers, setWorkers] = useState<WorkerData[]>([]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="px-2 sm:px-0 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-heading font-bold mb-2">
              Workers
            </h1>
            <p className="text-muted-foreground text-sm sm:text-base">
              Manage background analysis workers
            </p>
          </div>
          <Button className="bg-gradient-primary hover:opacity-90">
            <Server className="h-4 w-4 mr-2" />
            Provision Worker
          </Button>
        </div>

        {/* Content */}
        <Card className="glass">
          <CardContent className="pt-6">
            {workers.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No Workers Active"
                description="There are currently no background workers running. Provision a new worker to speed up repository analysis."
                actionLabel="Start First Worker"
                onAction={() => alert("Worker provisioning would start here!")}
              />
            ) : (
              <div className="text-center py-12 text-muted-foreground">
                Workers list would render here.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
