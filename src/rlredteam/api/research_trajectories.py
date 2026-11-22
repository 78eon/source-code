"""Authenticated GET-only research reconstruction; no database or execution endpoints."""

import json
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from rlredteam.application.research_trajectories import ResearchTrajectoryReader, SelectionError


def router(authorize, reader=None):
    routes = APIRouter(prefix='/api/research/ppo-trajectories', dependencies=[Depends(authorize)])
    def invoke(call):
        try:
            return call()
        except SelectionError:
            raise HTTPException(422, 'Only recorded registered validation episodes can be selected') from None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(503, 'Frozen validation evidence unavailable or inconsistent; no substitute trajectory displayed') from None
    def episode(training_seed,topology_seed,evaluation_seed):
        return invoke(lambda:(reader or ResearchTrajectoryReader()).episode(training_seed,topology_seed,evaluation_seed))
    @routes.get('')
    def index(response:Response):
        response.headers['Cache-Control']='no-store'
        return invoke(lambda:(reader or ResearchTrajectoryReader()).index())
    @routes.get('/{training_seed}/{topology_seed}/{evaluation_seed}')
    def recorded_episode(training_seed:int,topology_seed:int,evaluation_seed:int,response:Response):
        response.headers['Cache-Control']='no-store'
        return episode(training_seed,topology_seed,evaluation_seed)
    @routes.get('/{training_seed}/{topology_seed}/{evaluation_seed}/export/{report_format}')
    def export(training_seed:int,topology_seed:int,evaluation_seed:int,report_format:Literal['html','pdf','json']):
        from rlredteam.application.research_trajectory_report import html_report,pdf_report
        data=episode(training_seed,topology_seed,evaluation_seed)
        body=html_report(data) if report_format=='html' else pdf_report(data) if report_format=='pdf' else json.dumps(data,indent=2,ensure_ascii=False)
        filename=f'research-ppo-{training_seed}-{topology_seed}-{evaluation_seed}.{report_format}'
        return Response(body,media_type={'html':'text/html','pdf':'application/pdf','json':'application/json'}[report_format],
                        headers={'Content-Disposition':f'attachment; filename="{filename}"','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
    return routes
